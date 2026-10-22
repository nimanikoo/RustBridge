//! Correctness tests for the raw (no-encryption) shared-memory request/echo flow used by the
//! latency benchmark. Exercises the two-ring protocol in-process (producer/consumer threads),
//! checking payload integrity across many repeated rounds and varied sizes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rustbridge_bench::payload;
use shared_ipc::{Consumer, Producer};

fn names() -> (String, String) {
    static N: AtomicUsize = AtomicUsize::new(0);
    let i = N.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    (format!("/rrq{pid}_{i}"), format!("/rrp{pid}_{i}"))
}

/// Responder: read a message from `req`, echo the exact bytes back on `resp`, for `rounds`.
fn spawn_responder(req: String, resp: String, rounds: usize) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut rx = Consumer::connect(&req, Duration::from_secs(10)).unwrap();
        let mut tx = Producer::create(&resp, 1 << 20).unwrap();
        for _ in 0..rounds {
            let msg = rx.recv().unwrap();
            let n = msg.len();
            let mut g = tx.reserve(n).unwrap();
            g.copy_from_slice(&msg);
            g.commit(n);
            drop(msg);
        }
    })
}

#[test]
fn raw_roundtrip_fixed_size_many_rounds() {
    let (req, resp) = names();
    const ROUNDS: usize = 20_000;
    let responder = spawn_responder(req.clone(), resp.clone(), ROUNDS);

    let mut tx = Producer::create(&req, 1 << 20).unwrap();
    let mut rx = Consumer::connect(&resp, Duration::from_secs(10)).unwrap();
    let want = payload(256);
    for i in 0..ROUNDS {
        let mut g = tx.reserve(want.len()).unwrap();
        g.copy_from_slice(&want);
        g.commit(want.len());
        let echo = rx.recv().unwrap();
        assert_eq!(&*echo, want.as_slice(), "echo mismatch at round {i}");
    }
    responder.join().unwrap();
}

#[test]
fn raw_roundtrip_varied_sizes_byte_exact() {
    let (req, resp) = names();
    // Sizes that are not multiples of the 8-byte record alignment, plus an empty payload.
    let sizes = [0usize, 1, 7, 64, 1000, 4095, 4096, 65535];
    let responder = spawn_responder(req.clone(), resp.clone(), sizes.len());

    let mut tx = Producer::create(&req, 1 << 20).unwrap();
    let mut rx = Consumer::connect(&resp, Duration::from_secs(10)).unwrap();
    for &size in &sizes {
        let want = payload(size);
        let mut g = tx.reserve(size).unwrap();
        g.copy_from_slice(&want);
        g.commit(size);
        let echo = rx.recv().unwrap();
        assert_eq!(echo.len(), size);
        assert_eq!(&*echo, want.as_slice(), "mismatch at size {size}");
    }
    responder.join().unwrap();
}
