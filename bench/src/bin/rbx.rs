//! Experimental transports and micro-benchmarks for the RustBridge benchmark suite.
//!
//! Every subcommand is a separate process role launched by the driver. Each prints one
//! `RBX role=... t_start=<ns> t_end=<ns> ...` line using the system-wide monotonic clock.
//!
//! Subcommands:
//!   shm-send / shm-recv     production ring + optional production AES-GCM framing
//!   uds-send / uds-recv     Unix domain stream socket, same framing
//!   file-send / file-recv   sender writes a staging file, receiver reads it after rename
//!   mmap-send / mmap-recv   like file-*, but both sides use mmap on the staging file
//!   copy                    single process read -> (seal -> open) -> write baseline
//!   aead                    in-memory AES-256-GCM seal/open micro-benchmark
//!   noop                    exits immediately (process spawn baseline)
//!   shm-exists              prints whether a shared memory segment exists

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use memmap2::{MmapMut, MmapOptions};
use rustbridge_bench::*;
use shared_ipc::crypto::{self, OVERHEAD, Opener, PREFIX_LEN, Sealer};
use shared_ipc::{Consumer, DEFAULT_CHUNK_SIZE, DEFAULT_RING_SIZE, Producer, ShmSegment};

fn main() -> Result<()> {
    let mut argv = std::env::args().skip(1);
    let cmd = argv.next().unwrap_or_default();
    let a = Args::parse(argv)?;
    match cmd.as_str() {
        "shm-send" => shm_send(&a),
        "shm-recv" => shm_recv(&a),
        "uds-send" => uds_send(&a),
        "uds-recv" => uds_recv(&a),
        "file-send" => file_send(&a),
        "file-recv" => file_recv(&a),
        "mmap-send" => mmap_send(&a),
        "mmap-recv" => mmap_recv(&a),
        "copy" => copy(&a),
        "aead" => aead(&a),
        "noop" => Ok(()),
        "shm-exists" => {
            let exists = ShmSegment::open(a.req("channel")?).is_ok();
            println!("{}", if exists { "exists" } else { "absent" });
            Ok(())
        }
        other => bail!("unknown subcommand {other:?}"),
    }
}

fn crypto_parts(a: &Args) -> Result<(Option<Sealer>, Option<Opener>, usize, usize)> {
    if a.bool("crypto") {
        let key = crypto::key_from_env()?;
        Ok((
            Some(Sealer::new(&key)?),
            Some(Opener::new(&key)),
            PREFIX_LEN,
            OVERHEAD,
        ))
    } else {
        Ok((None, None, 0, 0))
    }
}

fn wait_for_path(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

fn set_sockbuf(fd: i32, opt: libc::c_int, size: usize) -> Result<usize> {
    if size > 0 {
        let v = size as libc::c_int;
        // SAFETY: valid fd and option value pointer.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&v as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as u32,
            )
        };
        ensure!(rc == 0, "setsockopt: {}", std::io::Error::last_os_error());
    }
    let mut v: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: valid fd and out-pointers.
    unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    Ok(v as usize)
}

// ---------------------------------------------------------------- shared memory ring

fn shm_send(a: &Args) -> Result<()> {
    let chunk = a.num("chunk", DEFAULT_CHUNK_SIZE)?;
    let (mut sealer, _, prefix, overhead) = crypto_parts(a)?;
    let mut src = Source::open(a)?;
    let mut producer = Producer::create(a.req("channel")?, a.num("ring", DEFAULT_RING_SIZE)?)?;
    ensure!(
        chunk + overhead <= producer.max_message_len(),
        "chunk does not fit in ring"
    );

    let t0 = now_ns();
    let mut sent = 0u64;
    loop {
        // Mirrors the production writer: read straight into the ring slot, seal in place.
        let mut grant = producer.reserve(chunk + overhead)?;
        let n = src.read_full(&mut grant[prefix..prefix + chunk])?;
        if n == 0 {
            break;
        }
        if let Some(s) = &mut sealer {
            s.seal_in_place(&mut grant[..n + overhead], false)?;
        }
        grant.commit(n + overhead);
        sent += n as u64;
    }
    let mut grant = producer.reserve(overhead)?;
    if let Some(s) = &mut sealer {
        s.seal_in_place(&mut grant, true)?;
    }
    grant.commit(overhead);
    producer.wait_until_drained()?;
    report(
        "send",
        &[
            ("t_start", t0.to_string()),
            ("t_end", now_ns().to_string()),
            ("bytes", sent.to_string()),
        ],
    );
    Ok(())
}

fn shm_recv(a: &Args) -> Result<()> {
    let (_, mut opener, _, _) = crypto_parts(a)?;
    let mut consumer = Consumer::connect(a.req("channel")?, Duration::from_secs(30))?;
    let t0 = now_ns();
    let mut sink = Sink::open(a)?;
    let result: Result<()> = (|| loop {
        let mut msg = consumer.recv()?;
        let (data, last): (&[u8], bool) = match &mut opener {
            Some(o) => o.open_in_place(&mut msg)?,
            None => {
                let last = msg.is_empty();
                (&*msg, last)
            }
        };
        if last {
            ensure!(data.is_empty(), "unexpected data in end-of-stream frame");
            return Ok(());
        }
        sink.write(data)?;
    })();
    finish_recv(sink, result, t0)
}

fn finish_recv(sink: Sink, result: Result<()>, t0: u64) -> Result<()> {
    if let Err(e) = result {
        sink.abort();
        return Err(e);
    }
    let bytes = sink.bytes;
    let hash = sink.finish()?;
    let mut fields = vec![
        ("t_start", t0.to_string()),
        ("t_end", now_ns().to_string()),
        ("bytes", bytes.to_string()),
    ];
    if let Some(h) = hash {
        fields.push(("sha256", h));
    }
    report("recv", &fields);
    Ok(())
}

// ---------------------------------------------------------------- unix domain sockets

fn uds_send(a: &Args) -> Result<()> {
    let chunk = a.num("chunk", DEFAULT_CHUNK_SIZE)?;
    let (sealer, _, _, _) = crypto_parts(a)?;
    let mut src = Source::open(a)?;
    let path = a.req("socket")?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match UnixStream::connect(path) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            Err(e) => return Err(e).context("connecting"),
        }
    };
    let sndbuf = set_sockbuf(stream.as_raw_fd(), libc::SO_SNDBUF, a.num("sockbuf", 0)?)?;

    let t0 = now_ns();
    let mut frames = FrameWriter::new(chunk, sealer);
    while let Some(rec) = frames.next_record(&mut src)? {
        stream.write_all(rec)?;
    }
    report(
        "send",
        &[
            ("t_start", t0.to_string()),
            ("t_end", now_ns().to_string()),
            ("bytes", src.len().to_string()),
            ("sndbuf", sndbuf.to_string()),
        ],
    );
    Ok(())
}

fn uds_recv(a: &Args) -> Result<()> {
    let (_, opener, _, _) = crypto_parts(a)?;
    let path = a.req("socket")?;
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path).context("binding socket")?;
    // Set on the listener so the accepted socket inherits it before any data arrives (macOS
    // rejects setsockopt on an accepted socket whose peer has already disconnected).
    set_sockbuf(listener.as_raw_fd(), libc::SO_RCVBUF, a.num("sockbuf", 0)?)?;
    let (stream, _) = listener.accept()?;
    let _ = fs::remove_file(path);
    let rcvbuf = set_sockbuf(stream.as_raw_fd(), libc::SO_RCVBUF, 0)?;
    let t0 = now_ns();
    let mut sink = Sink::open(a)?;
    let mut frames = FrameReader::new(stream, opener);
    let result: Result<()> = (|| {
        while let Some(data) = frames.next_chunk()? {
            sink.write(data)?;
        }
        Ok(())
    })();
    eprintln!("rcvbuf={rcvbuf}");
    finish_recv(sink, result, t0)
}

// ---------------------------------------------------------------- staged file

fn file_send(a: &Args) -> Result<()> {
    let chunk = a.num("chunk", DEFAULT_CHUNK_SIZE)?;
    let (sealer, _, _, _) = crypto_parts(a)?;
    let mut src = Source::open(a)?;
    let staging = Path::new(a.req("staging")?);
    let tmp = staging.with_extension("tmp");

    let t0 = now_ns();
    let mut f = File::create(&tmp)?;
    let mut frames = FrameWriter::new(chunk, sealer);
    while let Some(rec) = frames.next_record(&mut src)? {
        f.write_all(rec)?;
    }
    // No fsync: the staging file is a transport, not durable output. Rename publishes it.
    drop(f);
    fs::rename(&tmp, staging)?;
    report(
        "send",
        &[
            ("t_start", t0.to_string()),
            ("t_end", now_ns().to_string()),
            ("bytes", src.len().to_string()),
        ],
    );
    Ok(())
}

fn file_recv(a: &Args) -> Result<()> {
    let (_, opener, _, _) = crypto_parts(a)?;
    let staging = Path::new(a.req("staging")?);
    wait_for_path(staging, Duration::from_secs(30))?;
    let t0 = now_ns();
    let mut sink = Sink::open(a)?;
    let mut frames = FrameReader::new(File::open(staging)?, opener);
    let result: Result<()> = (|| {
        while let Some(data) = frames.next_chunk()? {
            sink.write(data)?;
        }
        Ok(())
    })();
    let _ = fs::remove_file(staging);
    finish_recv(sink, result, t0)
}

// ---------------------------------------------------------------- staged mmap

fn mmap_send(a: &Args) -> Result<()> {
    let chunk = a.num("chunk", DEFAULT_CHUNK_SIZE)?;
    let (mut sealer, _, prefix, overhead) = crypto_parts(a)?;
    let mut src = Source::open(a)?;
    let staging = Path::new(a.req("staging")?);
    let tmp = staging.with_extension("tmp");
    let len = src.len() as usize;
    let chunks = len.div_ceil(chunk);
    let total = chunks * (LEN_PREFIX + overhead) + len + LEN_PREFIX + overhead;

    let t0 = now_ns();
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    file.set_len(total as u64)?;
    // SAFETY: the staging file is private to this transfer until it is renamed.
    let mut map = unsafe { MmapMut::map_mut(&file)? };
    let mut pos = 0;
    let mut remaining = len;
    loop {
        let n = remaining.min(chunk);
        let frame = n + overhead;
        map[pos..pos + LEN_PREFIX].copy_from_slice(&(frame as u32).to_le_bytes());
        let body = pos + LEN_PREFIX;
        if n > 0 {
            let got = src.read_full(&mut map[body + prefix..body + prefix + n])?;
            ensure!(got == n, "source shrank during transfer");
        }
        if let Some(s) = &mut sealer {
            s.seal_in_place(&mut map[body..body + frame], n == 0)?;
        }
        pos = body + frame;
        remaining -= n;
        if n == 0 {
            break;
        }
    }
    ensure!(pos == total, "staging size mismatch");
    drop(map);
    drop(file);
    fs::rename(&tmp, staging)?;
    report(
        "send",
        &[
            ("t_start", t0.to_string()),
            ("t_end", now_ns().to_string()),
            ("bytes", len.to_string()),
        ],
    );
    Ok(())
}

fn mmap_recv(a: &Args) -> Result<()> {
    let (_, mut opener, _, _) = crypto_parts(a)?;
    let staging = Path::new(a.req("staging")?);
    wait_for_path(staging, Duration::from_secs(30))?;
    let t0 = now_ns();
    let mut sink = Sink::open(a)?;
    let file = File::open(staging)?;
    // Private (copy-on-write) mapping: decrypting in place must not write back to the file.
    // SAFETY: the sender has finished and renamed the file; nobody else modifies it.
    let mut map = unsafe { MmapOptions::new().map_copy(&file)? };
    let result: Result<()> = (|| {
        let mut pos = 0;
        loop {
            ensure!(pos + LEN_PREFIX <= map.len(), "staging file truncated");
            let len = u32::from_le_bytes(map[pos..pos + LEN_PREFIX].try_into().unwrap()) as usize;
            let body = pos + LEN_PREFIX;
            ensure!(body + len <= map.len(), "staging frame truncated");
            pos = body + len;
            let (data, last): (&[u8], bool) = match &mut opener {
                Some(o) => o.open_in_place(&mut map[body..body + len])?,
                None => (&map[body..body + len], len == 0),
            };
            if last {
                ensure!(data.is_empty(), "unexpected data in end-of-stream frame");
                return Ok(());
            }
            sink.write(data)?;
        }
    })();
    drop(map);
    let _ = fs::remove_file(staging);
    finish_recv(sink, result, t0)
}

// ---------------------------------------------------------------- single-process baseline

fn copy(a: &Args) -> Result<()> {
    let chunk = a.num("chunk", DEFAULT_CHUNK_SIZE)?;
    let (mut sealer, mut opener, prefix, overhead) = crypto_parts(a)?;
    let mut src = Source::open(a)?;
    let t0 = now_ns();
    let mut sink = Sink::open(a)?;
    let mut buf = vec![0u8; chunk + OVERHEAD];
    let result: Result<()> = (|| {
        loop {
            let n = src.read_full(&mut buf[prefix..prefix + chunk])?;
            let frame = &mut buf[..n + overhead];
            let data: &[u8] = match (&mut sealer, &mut opener) {
                (Some(s), Some(o)) => {
                    s.seal_in_place(frame, n == 0)?;
                    o.open_in_place(frame)?.0
                }
                _ => frame,
            };
            if n == 0 {
                return Ok(());
            }
            sink.write(data)?;
        }
    })();
    finish_recv(sink, result, t0)
}

// ---------------------------------------------------------------- AEAD micro-benchmark

/// Seals then opens `--size` bytes split into `--chunk` frames, `--reps` times, in memory.
/// Prints one CSV line per repetition: chunk,size,rep,seal_ns,open_ns,verified
fn aead(a: &Args) -> Result<()> {
    let chunk = a.num("chunk", DEFAULT_CHUNK_SIZE)?;
    let size = a.num("size", 1 << 20)?;
    let reps = a.num("reps", 10)?;
    ensure!(chunk > 0, "chunk must be non-zero");
    let key = [0x42u8; crypto::KEY_LEN];
    let plain = payload(size);
    let expected = sha256_hex(&plain);

    // Frames laid out back to back, exactly as they would be built for the transports.
    let mut spans = Vec::new();
    let mut off = 0;
    for start in (0..size.max(1)).step_by(chunk) {
        let n = chunk.min(size - start.min(size));
        spans.push((off, n));
        off += n + OVERHEAD;
    }
    let mut frames = vec![0u8; off];

    for rep in 0..reps {
        for (i, &(o, n)) in spans.iter().enumerate() {
            let s = i * chunk;
            frames[o + PREFIX_LEN..o + PREFIX_LEN + n].copy_from_slice(&plain[s..s + n]);
        }
        let mut sealer = Sealer::new(&key)?;
        let t0 = now_ns();
        for &(o, n) in &spans {
            sealer.seal_in_place(&mut frames[o..o + n + OVERHEAD], false)?;
        }
        let t1 = now_ns();
        let mut opener = Opener::new(&key);
        for &(o, n) in &spans {
            opener.open_in_place(&mut frames[o..o + n + OVERHEAD])?;
        }
        let t2 = now_ns();

        let mut out = Vec::with_capacity(size);
        for &(o, n) in &spans {
            out.extend_from_slice(&frames[o + PREFIX_LEN..o + PREFIX_LEN + n]);
        }
        let ok = sha256_hex(&out) == expected;
        println!("{chunk},{size},{rep},{},{},{ok}", t1 - t0, t2 - t1);
    }
    Ok(())
}
