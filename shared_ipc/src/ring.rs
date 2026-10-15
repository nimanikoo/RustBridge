//! Lock-free single-producer / single-consumer message ring in POSIX shared memory.
//!
//! Layout of the segment:
//!
//! ```text
//! [ Header (3 cache lines) | data: capacity bytes (power of two) ]
//! ```
//!
//! `head` and `tail` are monotonically increasing byte positions; the slot offset is
//! `pos & (capacity - 1)`. Each record is `[len: u32][reserved: u32][payload]`, padded to
//! 8 bytes. A record never straddles the end of the buffer: if it would not fit, the
//! producer writes a `WRAP` marker and continues at offset 0.
//!
//! The producer publishes with a `Release` store of `head`; the consumer frees space with a
//! `Release` store of `tail`. Each side caches the other's index and only re-reads it when
//! it looks full/empty, keeping cross-core cache traffic to a minimum.
//!
//! Wakeups are hybrid. A waiter first spins and yields (the lock-free fast path, unchanged);
//! only when that budget is exhausted does it block on a process-shared pthread condvar that
//! lives inside the segment (see [`WaitSet`]), woken by its peer. This removes the old 50 µs
//! sleep-polling from the idle path while leaving the streaming path lock-free.

use std::cell::UnsafeCell;
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::shm::ShmSegment;

// Layout version 2: added the in-segment WaitSet. The byte was 0x01 in version 1, so an old
// peer (which checks this exact value) can never attach to a new-layout segment, or vice versa.
const MAGIC: u64 = 0x5242_5249_4447_4502; // "RBRIDGE" + layout version 2
const WRAP: u32 = u32::MAX;
/// `consumer_pid` value before any consumer has attached.
const NO_CONSUMER: u32 = 0;
/// `consumer_pid` value after a consumer detached, so the producer stops waiting for it.
const DETACHED: u32 = u32::MAX;
const RECORD_HEADER: usize = 8;
const ALIGN: usize = 8;

/// Smallest accepted ring capacity.
pub const MIN_CAPACITY: usize = 4096;

#[repr(C, align(64))]
struct CachePadded<T>(T);

/// How long a parked waiter blocks on the condvar before waking to re-check the ring and the
/// peer's liveness. It is purely a safety net: in the common case the peer's `sem_post`-style
/// `pthread_cond_signal` wakes the waiter immediately. The timeout only bounds the rare
/// lost-wakeup window (see [`WaitSet::park_until`]) and the time to notice a peer that was
/// SIGKILLed while the survivor is parked.
const PARK_TIMEOUT: Duration = Duration::from_micros(200);

/// Fallback sleep used only when the shared mutex cannot be acquired promptly (e.g. a peer
/// died holding it). Keeps a parked waiter from ever blocking indefinitely on the mutex.
const FALLBACK_SLEEP: Duration = Duration::from_micros(50);

/// Process-shared blocking primitives living inside the segment, on their own cache line(s)
/// after `head`/`tail` so the lock-free streaming path never false-shares with them.
///
/// One mutex guards two condvars (classic bounded-buffer): `data_available` is signalled by
/// the producer after it publishes a frame, `space_available` by the consumer after it frees
/// one. Two condvars rather than one shared semaphore because the producer (in
/// `wait_for_space`/`wait_until_drained`) and the consumer (in `recv`) can both be parked at
/// the same time and must be woken independently without spurious cross-wakeups.
///
/// The `pthread_*_t` objects are initialised in place by the producer in [`Producer::create`]
/// and never moved or copied afterwards (they live at a fixed address in the mapping).
#[repr(C, align(64))]
struct WaitSet {
    mutex: UnsafeCell<libc::pthread_mutex_t>,
    data_available: UnsafeCell<libc::pthread_cond_t>,
    space_available: UnsafeCell<libc::pthread_cond_t>,
    /// Non-zero while a consumer is (about to be) parked on `data_available`. The producer
    /// reads it on the hot path and only locks + signals when a waiter is actually parked.
    consumer_parked: AtomicU32,
    /// Non-zero while a producer is (about to be) parked on `space_available`.
    producer_parked: AtomicU32,
}

#[repr(C)]
struct Header {
    magic: AtomicU64,
    capacity: AtomicU64,
    producer_pid: AtomicU32,
    consumer_pid: AtomicU32,
    head: CachePadded<AtomicU64>,
    tail: CachePadded<AtomicU64>,
    wait: WaitSet,
}

const HEADER_SIZE: usize = std::mem::size_of::<Header>();

/// Converts a `pthread_*` return value (0 on success, an errno otherwise) into `io::Result`.
fn cvt(ret: libc::c_int) -> io::Result<()> {
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(ret))
    }
}

/// Absolute `CLOCK_REALTIME` deadline `timeout` from now, for `pthread_cond_timedwait`.
fn deadline(timeout: Duration) -> libc::timespec {
    // SAFETY: valid out-pointer; CLOCK_REALTIME is the clock pthread condvars use by default.
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    let mut nsec = now.tv_nsec as i64 + timeout.subsec_nanos() as i64;
    let mut sec = now.tv_sec as i64 + timeout.as_secs() as i64;
    if nsec >= 1_000_000_000 {
        sec += 1;
        nsec -= 1_000_000_000;
    }
    libc::timespec {
        tv_sec: sec as libc::time_t,
        tv_nsec: nsec as _,
    }
}

impl WaitSet {
    /// Initialises the mutex and both condvars as process-shared. Producer-only; called
    /// before the segment's `MAGIC` is published, so a consumer that sees `MAGIC` can rely on
    /// these being ready. Returns the first libc error if any step fails.
    ///
    /// # Safety
    /// `self` must point into a live, zero-initialised mapping that no peer is using yet.
    unsafe fn init(&self) -> io::Result<()> {
        unsafe {
            let mut mattr: libc::pthread_mutexattr_t = std::mem::zeroed();
            cvt(libc::pthread_mutexattr_init(&mut mattr))?;
            let mattr_shared =
                libc::pthread_mutexattr_setpshared(&mut mattr, libc::PTHREAD_PROCESS_SHARED);
            let mutex_init = if mattr_shared == 0 {
                libc::pthread_mutex_init(self.mutex.get(), &mattr)
            } else {
                mattr_shared
            };
            libc::pthread_mutexattr_destroy(&mut mattr);
            cvt(mutex_init)?;

            let mut cattr: libc::pthread_condattr_t = std::mem::zeroed();
            cvt(libc::pthread_condattr_init(&mut cattr))?;
            let cattr_shared =
                libc::pthread_condattr_setpshared(&mut cattr, libc::PTHREAD_PROCESS_SHARED);
            let (cond1, cond2) = if cattr_shared == 0 {
                (
                    libc::pthread_cond_init(self.data_available.get(), &cattr),
                    libc::pthread_cond_init(self.space_available.get(), &cattr),
                )
            } else {
                (cattr_shared, cattr_shared)
            };
            libc::pthread_condattr_destroy(&mut cattr);
            cvt(cond1)?;
            cvt(cond2)?;
        }
        self.consumer_parked.store(0, Ordering::Relaxed);
        self.producer_parked.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Destroys the primitives. Producer-only, and must run while the mapping is still valid
    /// (before `munmap`/`shm_unlink`). Errors are ignored: a condvar/mutex with a surviving
    /// waiter reports `EBUSY`, which is harmless at teardown.
    ///
    /// # Safety
    /// `self` must point into a still-mapped segment that this process created.
    unsafe fn destroy(&self) {
        unsafe {
            libc::pthread_cond_destroy(self.space_available.get());
            libc::pthread_cond_destroy(self.data_available.get());
            libc::pthread_mutex_destroy(self.mutex.get());
        }
    }

    /// Blocks until `progress()` holds or `PARK_TIMEOUT` elapses, returning whether progress
    /// was observed. `parked` is the waiter's own parked-flag; `cond` is the condvar the peer
    /// signals.
    ///
    /// Lost-wakeup ordering (documented because it is subtle):
    /// 1. Store `parked = 1` (SeqCst) *before* the final predicate check, so any peer that
    ///    publishes progress after our check still sees us parked and signals.
    /// 2. Re-check `progress()` after arming, then again under the mutex. Either check seeing
    ///    progress means we never block.
    /// 3. The wake side holds the same mutex around `pthread_cond_signal`, so it cannot slip a
    ///    signal into the window between our under-lock check and entering `cond_timedwait`.
    /// 4. As a final safety net for the residual store/load race on the two parked flags
    ///    (deliberately not SeqCst-fenced against the Release index stores, to keep the
    ///    streaming path lock-free), `cond_timedwait` returns after `PARK_TIMEOUT` and we
    ///    re-check. Worst case this degrades to ~200 µs polling; it can never hang.
    ///
    /// # Safety
    /// `self`/`cond` must point into the live, initialised mapping.
    unsafe fn park_until(
        &self,
        cond: *mut libc::pthread_cond_t,
        parked: &AtomicU32,
        mut progress: impl FnMut() -> bool,
    ) -> io::Result<bool> {
        parked.store(1, Ordering::SeqCst);
        if progress() {
            parked.store(0, Ordering::SeqCst);
            return Ok(true);
        }
        unsafe {
            // Non-blocking lock: a peer that was SIGKILLed while briefly holding the mutex must
            // never wedge the survivor. If we cannot take it at once, fall back to a short sleep
            // and let the caller re-check progress and peer liveness.
            if libc::pthread_mutex_trylock(self.mutex.get()) != 0 {
                std::thread::sleep(FALLBACK_SLEEP);
                return Ok(progress());
            }
            let result = if progress() {
                Ok(true)
            } else {
                let ts = deadline(PARK_TIMEOUT);
                match libc::pthread_cond_timedwait(cond, self.mutex.get(), &ts) {
                    0 => Ok(progress()),
                    e if e == libc::ETIMEDOUT => Ok(progress()),
                    e => Err(io::Error::from_raw_os_error(e)),
                }
            };
            cvt(libc::pthread_mutex_unlock(self.mutex.get()))?;
            if matches!(result, Ok(true)) {
                parked.store(0, Ordering::SeqCst);
            }
            result
        }
    }

    /// Wakes a peer parked on `cond`, but only if its `parked` flag is set, so the streaming
    /// hot path stays lock-free when no one is waiting. If the mutex is momentarily held, the
    /// signal is skipped: the parked peer's `PARK_TIMEOUT` covers that case.
    ///
    /// # Safety
    /// `self`/`cond` must point into the live, initialised mapping.
    unsafe fn wake(&self, cond: *mut libc::pthread_cond_t, parked: &AtomicU32) {
        if parked.load(Ordering::SeqCst) == 0 {
            return;
        }
        unsafe {
            if libc::pthread_mutex_trylock(self.mutex.get()) != 0 {
                return;
            }
            libc::pthread_cond_signal(cond);
            libc::pthread_mutex_unlock(self.mutex.get());
        }
    }
}

struct Ring {
    seg: ShmSegment,
    capacity: usize,
}

impl Ring {
    fn header(&self) -> &Header {
        // SAFETY: the segment is page aligned and at least HEADER_SIZE bytes long.
        unsafe { &*(self.seg.as_ptr() as *const Header) }
    }

    fn data(&self) -> *mut u8 {
        // SAFETY: the data area directly follows the header inside the mapping.
        unsafe { self.seg.as_ptr().add(HEADER_SIZE) }
    }

    fn offset(&self, pos: u64) -> usize {
        (pos as usize) & (self.capacity - 1)
    }

    fn write_len(&self, offset: usize, len: u32) {
        // SAFETY: offset is 8-aligned and offset + 4 <= capacity.
        unsafe { (self.data().add(offset) as *mut u32).write(len) }
    }

    fn read_len(&self, offset: usize) -> u32 {
        // SAFETY: offset is 8-aligned and offset + 4 <= capacity.
        unsafe { (self.data().add(offset) as *const u32).read() }
    }
}

fn record_size(len: usize) -> usize {
    (RECORD_HEADER + len).next_multiple_of(ALIGN)
}

/// Writing half of a channel. Creates (and on drop removes) the shared memory segment.
pub struct Producer {
    ring: Ring,
    head: u64,
    cached_tail: u64,
}

impl Producer {
    /// Creates a new channel with a ring of `capacity` bytes (a power of two, at least 4 KiB).
    pub fn create(name: &str, capacity: usize) -> io::Result<Self> {
        if !capacity.is_power_of_two() || capacity < MIN_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("ring capacity must be a power of two >= {MIN_CAPACITY}, got {capacity}"),
            ));
        }
        let seg = ShmSegment::create(name, HEADER_SIZE + capacity)?;
        let ring = Ring { seg, capacity };
        let header = ring.header();
        header.capacity.store(capacity as u64, Ordering::Relaxed);
        header
            .producer_pid
            .store(std::process::id(), Ordering::Relaxed);
        // Initialise the in-segment wait set before publishing MAGIC, so a consumer that sees
        // MAGIC can safely use the mutex/condvars. The pages came zeroed from ftruncate.
        // SAFETY: fresh mapping owned solely by this process; no peer is attached yet.
        unsafe { header.wait.init()? };
        // Publishing the magic last tells consumers that the header is fully initialised.
        header.magic.store(MAGIC, Ordering::Release);
        Ok(Self {
            ring,
            head: 0,
            cached_tail: 0,
        })
    }

    /// Largest payload a single message can carry.
    pub fn max_message_len(&self) -> usize {
        self.ring.capacity - RECORD_HEADER
    }

    /// Blocks until `len` bytes are free, then returns a writable slot for the payload.
    /// Nothing is visible to the consumer until [`Grant::commit`] is called.
    pub fn reserve(&mut self, len: usize) -> io::Result<Grant<'_>> {
        if len > self.max_message_len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "message of {len} bytes exceeds ring limit of {}",
                    self.max_message_len()
                ),
            ));
        }
        let need = record_size(len);
        let offset = self.ring.offset(self.head);
        let contiguous = self.ring.capacity - offset;
        if contiguous < need {
            // Skip the tail end of the buffer. `contiguous` is always >= 8 because every
            // offset is 8-aligned, so the marker fits.
            self.wait_for_space(contiguous)?;
            self.ring.write_len(offset, WRAP);
            self.head += contiguous as u64;
            self.ring
                .header()
                .head
                .0
                .store(self.head, Ordering::Release);
        }
        self.wait_for_space(need)?;
        let offset = self.ring.offset(self.head);
        Ok(Grant {
            producer: self,
            offset,
            len,
        })
    }

    /// Copies `data` into the ring as one message.
    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let mut grant = self.reserve(data.len())?;
        grant.copy_from_slice(data);
        grant.commit(data.len());
        Ok(())
    }

    /// Blocks until the consumer has attached and read every published message.
    pub fn wait_until_drained(&mut self) -> io::Result<()> {
        let mut backoff = Backoff::new();
        loop {
            self.cached_tail = self.ring.header().tail.0.load(Ordering::Acquire);
            if self.cached_tail == self.head {
                return Ok(());
            }
            if backoff.should_park() {
                let head = self.head;
                let header = self.ring.header();
                // SAFETY: wait set was initialised by this producer before MAGIC was published.
                unsafe {
                    header.wait.park_until(
                        header.wait.space_available.get(),
                        &header.wait.producer_parked,
                        || header.tail.0.load(Ordering::Acquire) == head,
                    )?;
                }
                // Parked == idle: cheaply confirm the consumer is still alive each wake so a
                // SIGKILLed consumer can never leave us blocked forever.
                self.check_consumer()?;
            }
        }
    }

    fn wait_for_space(&mut self, need: usize) -> io::Result<()> {
        let capacity = self.ring.capacity as u64;
        if capacity - (self.head - self.cached_tail) >= need as u64 {
            return Ok(());
        }
        let mut backoff = Backoff::new();
        loop {
            self.cached_tail = self.ring.header().tail.0.load(Ordering::Acquire);
            if capacity - (self.head - self.cached_tail) >= need as u64 {
                return Ok(());
            }
            if backoff.should_park() {
                let head = self.head;
                let need = need as u64;
                let header = self.ring.header();
                // SAFETY: as above.
                unsafe {
                    header.wait.park_until(
                        header.wait.space_available.get(),
                        &header.wait.producer_parked,
                        || capacity - (head - header.tail.0.load(Ordering::Acquire)) >= need,
                    )?;
                }
                self.check_consumer()?;
            }
        }
    }

    fn check_consumer(&self) -> io::Result<()> {
        match self.ring.header().consumer_pid.load(Ordering::Relaxed) {
            // No consumer has attached yet; keep waiting for one.
            NO_CONSUMER => Ok(()),
            DETACHED => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "consumer detached before reading everything",
            )),
            pid if !process_alive(pid) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("consumer (pid {pid}) exited"),
            )),
            _ => Ok(()),
        }
    }
}

impl Drop for Producer {
    fn drop(&mut self) {
        // Destroy the process-shared mutex/condvars while the mapping is still valid. This
        // runs before the `ShmSegment` field's own Drop (which does munmap + shm_unlink),
        // because a type's Drop::drop runs before its fields are dropped. Only the producer
        // (the segment owner) destroys them; the consumer never does.
        // SAFETY: the segment is still mapped here; `wait` was initialised in `create`.
        unsafe { self.ring.header().wait.destroy() };
    }
}

/// A reserved, not yet published, message slot.
pub struct Grant<'a> {
    producer: &'a mut Producer,
    offset: usize,
    len: usize,
}

impl Grant<'_> {
    /// Publishes the first `len` bytes of the slot (`len` may be smaller than reserved).
    pub fn commit(self, len: usize) {
        assert!(
            len <= self.len,
            "commit length {len} exceeds reservation {}",
            self.len
        );
        let producer = self.producer;
        producer.ring.write_len(self.offset, len as u32);
        producer.head += record_size(len) as u64;
        let header = producer.ring.header();
        header.head.0.store(producer.head, Ordering::Release);
        // Wake a consumer parked in `recv`. No-op (one atomic load) when none is parked, so the
        // streaming path stays lock-free. Must follow the Release store above so the woken
        // consumer sees the new `head`.
        // SAFETY: wait set initialised in `create`; segment mapped for the Grant's lifetime.
        unsafe { header.wait.wake(header.wait.data_available.get(), &header.wait.consumer_parked) };
    }
}

impl Deref for Grant<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: the slot lies inside the data area and is owned by the producer until commit.
        unsafe {
            std::slice::from_raw_parts(
                self.producer.ring.data().add(self.offset + RECORD_HEADER),
                self.len,
            )
        }
    }
}

impl DerefMut for Grant<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above; the consumer never reads unpublished slots.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.producer.ring.data().add(self.offset + RECORD_HEADER),
                self.len,
            )
        }
    }
}

/// Reading half of a channel. Only one consumer may be attached at a time.
pub struct Consumer {
    ring: Ring,
    tail: u64,
    cached_head: u64,
}

impl Consumer {
    /// Attaches to an existing channel. Returns `NotFound` if the producer has not created it yet.
    pub fn open(name: &str) -> io::Result<Self> {
        let seg = ShmSegment::open(name)?;
        if seg.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "segment not initialised yet",
            ));
        }
        // SAFETY: checked above that the header fits in the mapping.
        let header = unsafe { &*(seg.as_ptr() as *const Header) };
        if header.magic.load(Ordering::Acquire) != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "segment not initialised yet",
            ));
        }
        let capacity = header.capacity.load(Ordering::Relaxed) as usize;
        if !capacity.is_power_of_two()
            || capacity < MIN_CAPACITY
            || seg.len() < HEADER_SIZE + capacity
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "segment header is corrupt",
            ));
        }
        // A producer that was killed cannot unlink its segment. Treat it as absent so we keep
        // waiting for the next producer, which replaces the stale segment on startup.
        if !process_alive(header.producer_pid.load(Ordering::Relaxed)) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "stale segment left by an exited producer",
            ));
        }
        let me = std::process::id();
        let mut current = header.consumer_pid.load(Ordering::Acquire);
        loop {
            // Take the slot if it is free, was released, or its owner died without detaching.
            let free = current == NO_CONSUMER || current == DETACHED || !process_alive(current);
            if !free {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("another consumer (pid {current}) is already attached"),
                ));
            }
            match header.consumer_pid.compare_exchange(
                current,
                me,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let tail = header.tail.0.load(Ordering::Acquire);
        let cached_head = header.head.0.load(Ordering::Acquire);
        Ok(Self {
            ring: Ring { seg, capacity },
            tail,
            cached_head,
        })
    }

    /// Retries [`Consumer::open`] until the producer shows up or `timeout` elapses.
    ///
    /// Uses exponential backoff starting at 50 µs and doubling to a 5 ms cap, rather than a
    /// flat 10 ms sleep. When the producer is already up this drops first-attach latency from
    /// ~10 ms to well under 1 ms, while a long wait for an absent producer still costs almost
    /// no CPU.
    pub fn connect(name: &str, timeout: Duration) -> io::Result<Self> {
        const INITIAL_DELAY: Duration = Duration::from_micros(50);
        const MAX_DELAY: Duration = Duration::from_millis(5);
        let deadline = Instant::now() + timeout;
        let mut delay = INITIAL_DELAY;
        loop {
            match Self::open(name) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(e);
                    }
                    // Never sleep past the deadline, so the timeout stays accurate.
                    std::thread::sleep(delay.min(deadline - now));
                    delay = (delay * 2).min(MAX_DELAY);
                }
                other => return other,
            }
        }
    }

    /// Blocks until a message is available. The slot is released when the [`Message`] is dropped.
    pub fn recv(&mut self) -> io::Result<Message<'_>> {
        let mut backoff = Backoff::new();
        loop {
            if self.cached_head == self.tail {
                self.cached_head = self.ring.header().head.0.load(Ordering::Acquire);
                if self.cached_head == self.tail {
                    if backoff.should_park() {
                        let tail = self.tail;
                        let header = self.ring.header();
                        // SAFETY: wait set initialised by the producer before MAGIC; mapped here.
                        unsafe {
                            header.wait.park_until(
                                header.wait.data_available.get(),
                                &header.wait.consumer_parked,
                                || header.head.0.load(Ordering::Acquire) != tail,
                            )?;
                        }
                        // Parked == idle: confirm the producer is still alive on each wake.
                        self.check_producer()?;
                    }
                    continue;
                }
            }

            let offset = self.ring.offset(self.tail);
            let len = self.ring.read_len(offset);
            if len == WRAP {
                self.tail += (self.ring.capacity - offset) as u64;
                self.ring
                    .header()
                    .tail
                    .0
                    .store(self.tail, Ordering::Release);
                continue;
            }

            // Never trust lengths read from memory another process can write.
            let len = len as usize;
            let need = record_size(len);
            let available = (self.cached_head - self.tail) as usize;
            if offset + need > self.ring.capacity || need > available {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "corrupt record in ring",
                ));
            }
            return Ok(Message {
                consumer: self,
                offset,
                len,
            });
        }
    }

    fn check_producer(&self) -> io::Result<()> {
        let pid = self.ring.header().producer_pid.load(Ordering::Relaxed);
        if !process_alive(pid) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("producer (pid {pid}) exited"),
            ));
        }
        Ok(())
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        let _ = self.ring.header().consumer_pid.compare_exchange(
            std::process::id(),
            DETACHED,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
}

/// A received message, borrowed straight from shared memory (zero-copy).
pub struct Message<'a> {
    consumer: &'a mut Consumer,
    offset: usize,
    len: usize,
}

impl Deref for Message<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: bounds validated in recv; the producer does not touch the slot until released.
        unsafe {
            std::slice::from_raw_parts(
                self.consumer.ring.data().add(self.offset + RECORD_HEADER),
                self.len,
            )
        }
    }
}

impl DerefMut for Message<'_> {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above; the consumer owns the slot until it is released.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.consumer.ring.data().add(self.offset + RECORD_HEADER),
                self.len,
            )
        }
    }
}

impl Drop for Message<'_> {
    fn drop(&mut self) {
        let consumer = &mut *self.consumer;
        consumer.tail += record_size(self.len) as u64;
        let header = consumer.ring.header();
        header.tail.0.store(consumer.tail, Ordering::Release);
        // Wake a producer parked in `wait_for_space`/`wait_until_drained`. No-op when none is
        // parked. Must follow the Release store above so the woken producer sees the new `tail`.
        // SAFETY: wait set initialised by the producer; segment mapped for the Message lifetime.
        unsafe {
            header
                .wait
                .wake(header.wait.space_available.get(), &header.wait.producer_parked)
        };
    }
}

/// Fast-path waiting: spin briefly, then yield. Keeps latency low under load. Once this budget
/// is spent, callers switch to blocking on the condvar (see [`WaitSet::park_until`]) instead of
/// the old unconditional 50 µs sleep, so an idle waiter is woken by its peer, not by polling.
struct Backoff {
    step: u32,
}

impl Backoff {
    const SPIN_LIMIT: u32 = 64;
    const YIELD_LIMIT: u32 = 128;

    fn new() -> Self {
        Self { step: 0 }
    }

    /// Runs one spin or yield step. Returns `true` once the spin+yield budget is exhausted and
    /// the caller should block on the condvar. (Earlier versions returned a periodic
    /// liveness-check signal here; peer liveness is now checked on every park iteration, since
    /// each park is bounded by `PARK_TIMEOUT`.)
    fn should_park(&mut self) -> bool {
        let park = if self.step < Self::SPIN_LIMIT {
            for _ in 0..(1u32 << self.step.min(6)) {
                std::hint::spin_loop();
            }
            false
        } else if self.step < Self::YIELD_LIMIT {
            std::thread::yield_now();
            false
        } else {
            true
        };
        self.step = self.step.wrapping_add(1);
        park
    }
}

fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // Signal 0 performs only the existence/permission check.
    unsafe {
        libc::kill(pid, 0) == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn unique_name() -> String {
        static N: AtomicUsize = AtomicUsize::new(0);
        format!(
            "/rbt{}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[test]
    fn header_is_cache_line_padded() {
        // head and tail each keep their own 64-byte cache line (unchanged by adding the wait
        // set, which is appended after tail).
        assert_eq!(std::mem::offset_of!(Header, head), 64);
        assert_eq!(std::mem::offset_of!(Header, tail), 128);
        // The wait set starts on a fresh cache line, past tail, so the blocking primitives
        // never false-share with head or tail on the streaming path.
        let wait = std::mem::offset_of!(Header, wait);
        assert_eq!(wait % 64, 0, "wait set must be cache-line aligned");
        assert!(wait >= 192, "wait set must come after head/tail lines, got {wait}");
        // HEADER_SIZE is platform-dependent now: libc::pthread_mutex_t is 64 B on macOS but
        // 40 B on glibc, and pthread_cond_t differs too, so the total cannot be a single
        // hard-coded constant without breaking the Linux build. On this target it is:
        //   macOS/arm64: wait at 192, HEADER_SIZE 384.
        assert!(HEADER_SIZE >= wait + std::mem::size_of::<WaitSet>());
        assert_eq!(wait, 192);
    }

    #[test]
    fn rejects_bad_capacity_and_oversized_messages() {
        assert!(Producer::create(&unique_name(), 5000).is_err());
        let mut p = Producer::create(&unique_name(), MIN_CAPACITY).unwrap();
        assert!(p.reserve(MIN_CAPACITY).is_err());
        assert!(p.reserve(p.max_message_len()).is_ok());
    }

    #[test]
    fn open_before_create_is_not_found() {
        let err = Consumer::open(&unique_name()).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn only_one_consumer() {
        let name = unique_name();
        let _p = Producer::create(&name, MIN_CAPACITY).unwrap();
        let _c = Consumer::open(&name).unwrap();
        // Same pid is "alive", so a second attach must be refused.
        assert_eq!(
            Consumer::open(&name).err().unwrap().kind(),
            io::ErrorKind::AddrInUse
        );
    }

    #[test]
    fn streams_many_messages_across_threads_with_wraparound() {
        let name = unique_name();
        let mut producer = Producer::create(&name, MIN_CAPACITY).unwrap();
        let mut consumer = Consumer::open(&name).unwrap();
        const COUNT: usize = 20_000;

        let reader = std::thread::spawn(move || {
            for i in 0..COUNT {
                let msg = consumer.recv().unwrap();
                let expected_len = i % 777;
                assert_eq!(msg.len(), expected_len, "message {i}");
                assert!(
                    msg.iter().all(|&b| b == (i % 251) as u8),
                    "message {i} corrupted"
                );
            }
        });

        for i in 0..COUNT {
            let payload = vec![(i % 251) as u8; i % 777];
            producer.send(&payload).unwrap();
        }
        producer.wait_until_drained().unwrap();
        reader.join().unwrap();
    }

    #[test]
    fn producer_notices_consumer_detaching_early() {
        let name = unique_name();
        let mut producer = Producer::create(&name, MIN_CAPACITY).unwrap();
        let consumer = Consumer::open(&name).unwrap();
        producer.send(b"never read").unwrap();
        drop(consumer);
        let err = producer.wait_until_drained().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        // A new consumer may take over the released slot.
        assert!(Consumer::open(&name).is_ok());
    }

    #[test]
    fn parked_consumer_exits_when_producer_is_dead() {
        // Guards against the classic blocking-wait regression: a waiter that parks on the
        // condvar must still wake (via PARK_TIMEOUT) and detect a dead peer, not hang.
        let name = unique_name();
        let producer = Producer::create(&name, MIN_CAPACITY).unwrap();
        let mut consumer = Consumer::open(&name).unwrap();
        // Point producer_pid at a reaped child, simulating a producer SIGKILLed mid-stream.
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = child.id();
        child.wait().unwrap();
        consumer
            .ring
            .header()
            .producer_pid
            .store(dead_pid, Ordering::Relaxed);
        // No data will ever arrive: recv must park, time out, see the dead producer, and error.
        // Message does not implement Debug, so match rather than unwrap_err.
        let err = match consumer.recv() {
            Ok(_) => panic!("recv must fail, not hang"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        drop(producer);
    }

    #[test]
    fn parked_producer_exits_when_consumer_is_dead() {
        // Symmetric guard for the producer side (wait_for_space / wait_until_drained).
        let name = unique_name();
        let mut producer = Producer::create(&name, MIN_CAPACITY).unwrap();
        let consumer = Consumer::open(&name).unwrap();
        producer.send(b"one message, never read").unwrap();
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = child.id();
        child.wait().unwrap();
        // Forge a live-but-dead consumer pid so the detach sentinel is not used.
        producer
            .ring
            .header()
            .consumer_pid
            .store(dead_pid, Ordering::Relaxed);
        std::mem::forget(consumer); // don't let Drop set the DETACHED sentinel
        let err = producer.wait_until_drained().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn commit_shorter_than_reserved() {
        let name = unique_name();
        let mut producer = Producer::create(&name, MIN_CAPACITY).unwrap();
        let mut consumer = Consumer::open(&name).unwrap();
        let mut grant = producer.reserve(100).unwrap();
        grant[..3].copy_from_slice(b"abc");
        grant.commit(3);
        assert_eq!(&*consumer.recv().unwrap(), b"abc");
    }
}
