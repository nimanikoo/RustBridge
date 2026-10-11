//! Protocol-level correctness checks for the benchmark suite, written against the public
//! production `shared_ipc` API (no production code is modified). They complement the
//! production unit tests in shared_ipc/src/{ring,crypto}.rs.

use std::io::{self, Cursor};
use std::sync::atomic::{AtomicUsize, Ordering};

use rustbridge_bench::{FrameReader, FrameWriter, Source, payload};
use shared_ipc::crypto::{KEY_LEN, OVERHEAD, Opener, PREFIX_LEN, Sealer};
use shared_ipc::ring::MIN_CAPACITY;
use shared_ipc::{Consumer, Producer, ShmSegment};

const KEY: [u8; KEY_LEN] = [0x11; KEY_LEN];

fn unique_name() -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    format!(
        "/rbp{}_{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn sealed(sealer: &mut Sealer, plain: &[u8], last: bool) -> Vec<u8> {
    let mut f = vec![0u8; plain.len() + OVERHEAD];
    f[PREFIX_LEN..PREFIX_LEN + plain.len()].copy_from_slice(plain);
    sealer.seal_in_place(&mut f, last).unwrap();
    f
}

#[test]
fn duplicated_frame_is_rejected() {
    let mut s = Sealer::new(&KEY).unwrap();
    let a = sealed(&mut s, b"frame zero", false);
    let mut o = Opener::new(&KEY);
    assert!(o.open_in_place(&mut a.clone()).is_ok());
    assert!(
        o.open_in_place(&mut a.clone()).is_err(),
        "replayed frame accepted"
    );
}

#[test]
fn truncated_and_undersized_frames_are_rejected() {
    let mut s = Sealer::new(&KEY).unwrap();
    let a = sealed(&mut s, b"some payload bytes", false);
    let mut short = a[..a.len() - 1].to_vec();
    assert!(Opener::new(&KEY).open_in_place(&mut short).is_err());
    let mut tiny = vec![0u8; OVERHEAD - 1];
    assert!(Opener::new(&KEY).open_in_place(&mut tiny).is_err());
}

#[test]
fn every_single_bit_flip_is_detected() {
    let mut s = Sealer::new(&KEY).unwrap();
    let a = sealed(&mut s, b"0123456789abcdef", false);
    for byte in 0..a.len() {
        let mut f = a.clone();
        f[byte] ^= 0x01;
        assert!(
            Opener::new(&KEY).open_in_place(&mut f).is_err(),
            "flip at byte {byte} undetected"
        );
    }
}

#[test]
fn stream_truncation_is_detected_by_missing_end_frame() {
    // A stream whose end-of-stream frame was dropped must not decode to a complete stream.
    let data = payload(10_000);
    let mut src = Source::Mem { data, pos: 0 };
    let mut w = FrameWriter::new(4096, Some(Sealer::new(&KEY).unwrap()));
    let mut encoded = Vec::new();
    let mut records = Vec::new();
    while let Some(r) = w.next_record(&mut src).unwrap() {
        records.push(r.len());
        encoded.extend_from_slice(r);
    }
    let without_last = encoded.len() - records.last().unwrap();
    let mut r = FrameReader::new(
        Cursor::new(&encoded[..without_last]),
        Some(Opener::new(&KEY)),
    );
    let mut got = 0;
    let err = loop {
        match r.next_chunk() {
            Ok(Some(d)) => got += d.len(),
            Ok(None) => panic!("truncated stream reported as complete"),
            Err(e) => break e,
        }
    };
    assert_eq!(got, 10_000);
    assert!(err.to_string().contains("end-of-stream"), "{err}");
}

#[test]
fn reordered_stream_records_are_rejected() {
    let data = payload(3 * 4096);
    let mut src = Source::Mem { data, pos: 0 };
    let mut w = FrameWriter::new(4096, Some(Sealer::new(&KEY).unwrap()));
    let mut recs = Vec::new();
    while let Some(r) = w.next_record(&mut src).unwrap() {
        recs.push(r.to_vec());
    }
    recs.swap(0, 1);
    let mut r = FrameReader::new(Cursor::new(recs.concat()), Some(Opener::new(&KEY)));
    assert!(r.next_chunk().is_err());
}

#[test]
fn stream_roundtrip_odd_sizes_plain_and_aead() {
    for &len in &[0usize, 1, 4095, 4096, 4097, 1_000_003] {
        for crypto in [false, true] {
            let data = payload(len);
            let mut src = Source::Mem {
                data: data.clone(),
                pos: 0,
            };
            let mut w = FrameWriter::new(4096, crypto.then(|| Sealer::new(&KEY).unwrap()));
            let mut enc = Vec::new();
            while let Some(r) = w.next_record(&mut src).unwrap() {
                enc.extend_from_slice(r);
            }
            let mut r = FrameReader::new(Cursor::new(enc), crypto.then(|| Opener::new(&KEY)));
            let mut out = Vec::new();
            while let Some(d) = r.next_chunk().unwrap() {
                out.extend_from_slice(d);
            }
            assert_eq!(out, data, "len={len} crypto={crypto}");
        }
    }
}

#[test]
fn corrupted_ring_length_is_rejected_not_trusted() {
    let name = unique_name();
    let mut p = Producer::create(&name, MIN_CAPACITY).unwrap();
    let mut c = Consumer::open(&name).unwrap();
    p.send(b"hello").unwrap();
    // A third party maps the same segment and scribbles over the first record's length.
    // Data area starts after the 192-byte header (asserted by the production unit tests).
    let seg = ShmSegment::open(&name).unwrap();
    unsafe { (seg.as_ptr().add(192) as *mut u32).write(1_000_000) };
    let err = c.recv().err().expect("corrupt length accepted");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn backpressure_and_wraparound_with_odd_sizes_byte_exact() {
    // Tiny ring, message sizes that never align with the capacity: forces many wraps and a
    // producer that blocks on a full ring while the consumer is slower.
    let name = unique_name();
    let mut p = Producer::create(&name, MIN_CAPACITY).unwrap();
    let mut c = Consumer::open(&name).unwrap();
    let data = payload(2_000_003);
    let expected = data.clone();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        loop {
            let m = c.recv().unwrap();
            if m.is_empty() {
                break;
            }
            out.extend_from_slice(&m);
            if out.len() % 7 == 0 {
                std::thread::yield_now(); // make the consumer intermittently slow
            }
        }
        out
    });
    let mut off = 0;
    let mut i = 0;
    while off < data.len() {
        let n = [1, 999, 1001, 3000, 4088][i % 5].min(data.len() - off);
        p.send(&data[off..off + n]).unwrap();
        off += n;
        i += 1;
    }
    p.send(&[]).unwrap();
    p.wait_until_drained().unwrap();
    assert_eq!(reader.join().unwrap(), expected);
}

#[test]
fn reserve_exceeding_capacity_is_rejected() {
    let mut p = Producer::create(&unique_name(), MIN_CAPACITY).unwrap();
    assert_eq!(
        p.reserve(MIN_CAPACITY).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
}
