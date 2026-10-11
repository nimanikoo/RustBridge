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

use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::shm::ShmSegment;

const MAGIC: u64 = 0x5242_5249_4447_4501; // "RBRIDGE" + layout version 1
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

#[repr(C)]
struct Header {
    magic: AtomicU64,
    capacity: AtomicU64,
    producer_pid: AtomicU32,
    consumer_pid: AtomicU32,
    head: CachePadded<AtomicU64>,
    tail: CachePadded<AtomicU64>,
}

const HEADER_SIZE: usize = std::mem::size_of::<Header>();

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
            if backoff.snooze() {
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
            if backoff.snooze() {
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
        producer
            .ring
            .header()
            .head
            .0
            .store(producer.head, Ordering::Release);
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
    pub fn connect(name: &str, timeout: Duration) -> io::Result<Self> {
        let deadline = Instant::now() + timeout;
        loop {
            match Self::open(name) {
                Err(e) if e.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
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
                    if backoff.snooze() {
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
        consumer
            .ring
            .header()
            .tail
            .0
            .store(consumer.tail, Ordering::Release);
    }
}

/// Spin, then yield, then sleep. Keeps latency low under load without burning a core when idle.
struct Backoff {
    step: u32,
}

impl Backoff {
    const SPIN_LIMIT: u32 = 64;
    const YIELD_LIMIT: u32 = 128;
    const CHECK_EVERY: u32 = 1024;

    fn new() -> Self {
        Self { step: 0 }
    }

    /// Waits a little. Returns `true` periodically once sleeping, so the caller can check
    /// whether its peer process is still alive.
    fn snooze(&mut self) -> bool {
        if self.step < Self::SPIN_LIMIT {
            for _ in 0..(1u32 << self.step.min(6)) {
                std::hint::spin_loop();
            }
        } else if self.step < Self::YIELD_LIMIT {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_micros(50));
        }
        self.step = self.step.wrapping_add(1);
        self.step >= Self::YIELD_LIMIT && self.step.is_multiple_of(Self::CHECK_EVERY)
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
        assert_eq!(HEADER_SIZE, 192);
        assert_eq!(std::mem::offset_of!(Header, head), 64);
        assert_eq!(std::mem::offset_of!(Header, tail), 128);
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
