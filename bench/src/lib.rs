//! Helpers shared by the RustBridge benchmark binaries.
//!
//! Everything here is experimental benchmark code. It reuses the production `shared_ipc`
//! crate (ring buffer, AES-256-GCM framing) but is not part of the production binaries.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use shared_ipc::crypto::{OVERHEAD, Opener, PREFIX_LEN, Sealer};

/// Seed for the deterministic, incompressible benchmark payload.
pub const PAYLOAD_SEED: u64 = 0x5275_7374_4272_6964;

/// Upper bound on a single stream frame accepted by the stream-based receivers.
pub const MAX_FRAME: usize = 64 << 20;

/// Bytes of the `u32` length prefix used by the stream transports (UDS, staged files).
pub const LEN_PREFIX: usize = 4;

/// System-wide monotonic clock in nanoseconds (CLOCK_MONOTONIC_RAW). Comparable across
/// processes on the same machine, so sender and receiver timestamps can be subtracted.
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer; CLOCK_MONOTONIC_RAW is supported on macOS and Linux.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed");
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Fills `buf` with the payload bytes that live at byte `offset` of the payload stream.
/// `offset` must be a multiple of 8. The output is pseudo-random and incompressible.
pub fn fill_payload(offset: u64, buf: &mut [u8]) {
    assert!(offset.is_multiple_of(8), "payload offset must be 8-aligned");
    let first_word = offset / 8;
    for (i, chunk) in buf.chunks_mut(8).enumerate() {
        let word = splitmix64(
            PAYLOAD_SEED.wrapping_add((first_word + i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)),
        );
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
}

/// Generates the whole payload of `len` bytes in memory.
pub fn payload(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    fill_payload(0, &mut v);
    v
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn sha256_file(path: &std::path::Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Minimal `--key value` / `--flag` argument parser.
pub struct Args {
    map: HashMap<String, String>,
}

impl Args {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self> {
        let mut map = HashMap::new();
        let mut it = args.into_iter().peekable();
        while let Some(a) = it.next() {
            let key = a
                .strip_prefix("--")
                .ok_or_else(|| anyhow!("unexpected argument {a:?}"))?;
            let value = match it.peek() {
                Some(v) if !v.starts_with("--") => it.next().unwrap(),
                _ => "1".to_string(),
            };
            map.insert(key.to_string(), value);
        }
        Ok(Self { map })
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.map.get(k).map(String::as_str)
    }

    pub fn req(&self, k: &str) -> Result<&str> {
        self.get(k).ok_or_else(|| anyhow!("missing --{k}"))
    }

    pub fn num(&self, k: &str, default: usize) -> Result<usize> {
        match self.get(k) {
            Some(v) => v
                .parse()
                .with_context(|| format!("--{k} must be an integer")),
            None => Ok(default),
        }
    }

    /// Boolean option given as `--k 1` / `--k 0` (or bare `--k`).
    pub fn bool(&self, k: &str) -> bool {
        matches!(self.get(k), Some("1" | "true" | "on"))
    }
}

/// Nearest-rank percentile of already-sorted ascending samples. `p` is in 0..=100.
fn nearest_rank(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Distribution of latency samples, in nanoseconds. Used by the latency benchmark so the
/// requester process can report p50/p95/p99 etc. without shipping every raw sample.
#[derive(Clone)]
pub struct LatencyStats {
    pub n: usize,
    pub min: u64,
    pub p50: u64,
    pub p90: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
    pub mean: f64,
    pub stddev: f64,
}

impl LatencyStats {
    /// Sorts `samples` in place and summarises them. Percentiles below are only meaningful
    /// with enough samples (the latency bench uses tens of thousands).
    pub fn from_samples(samples: &mut [u64]) -> Self {
        assert!(!samples.is_empty(), "no latency samples");
        samples.sort_unstable();
        let n = samples.len();
        let sum: u128 = samples.iter().map(|&s| s as u128).sum();
        let mean = sum as f64 / n as f64;
        let var = samples
            .iter()
            .map(|&s| {
                let d = s as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n as f64;
        Self {
            n,
            min: samples[0],
            p50: nearest_rank(samples, 50.0),
            p90: nearest_rank(samples, 90.0),
            p95: nearest_rank(samples, 95.0),
            p99: nearest_rank(samples, 99.0),
            max: samples[n - 1],
            mean,
            stddev: var.sqrt(),
        }
    }

    /// `RBX role=...`-style fields, so the driver reuses its existing line parser.
    pub fn as_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("n", self.n.to_string()),
            ("min_ns", self.min.to_string()),
            ("p50_ns", self.p50.to_string()),
            ("p90_ns", self.p90.to_string()),
            ("p95_ns", self.p95.to_string()),
            ("p99_ns", self.p99.to_string()),
            ("max_ns", self.max.to_string()),
            ("mean_ns", format!("{:.1}", self.mean)),
            ("stddev_ns", format!("{:.1}", self.stddev)),
        ]
    }
}

/// Prints the single machine-readable result line consumed by the driver.
pub fn report(role: &str, fields: &[(&str, String)]) {
    let mut line = format!("RBX role={role}");
    for (k, v) in fields {
        line.push_str(&format!(" {k}={v}"));
    }
    println!("{line}");
}

/// Where a sender gets its bytes from.
pub enum Source {
    /// Ordinary `read(2)` from a file (page cache or disk).
    File { file: File, len: u64 },
    /// Pre-generated in-memory payload (isolates transport cost from source I/O).
    Mem { data: Vec<u8>, pos: usize },
}

impl Source {
    pub fn open(a: &Args) -> Result<Self> {
        if let Some(p) = a.get("input") {
            let file = File::open(p).with_context(|| format!("opening {p}"))?;
            let len = file.metadata()?.len();
            Ok(Source::File { file, len })
        } else if a.get("mem").is_some() {
            Ok(Source::Mem {
                data: payload(a.num("mem", 0)?),
                pos: 0,
            })
        } else {
            bail!("need --input PATH or --mem BYTES")
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Source::File { len, .. } => *len,
            Source::Mem { data, .. } => data.len() as u64,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fills `buf` completely unless the source ends first (same semantics as production).
    pub fn read_full(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Source::File { file, .. } => {
                let mut filled = 0;
                while filled < buf.len() {
                    match file.read(&mut buf[filled..]) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(filled)
            }
            Source::Mem { data, pos } => {
                let n = buf.len().min(data.len() - *pos);
                buf[..n].copy_from_slice(&data[*pos..*pos + n]);
                *pos += n;
                Ok(n)
            }
        }
    }
}

/// Where a receiver puts its bytes.
pub struct Sink {
    file: Option<(File, PathBuf, PathBuf)>,
    hasher: Option<Sha256>,
    pub bytes: u64,
}

impl Sink {
    /// `--output PATH` writes `PATH.part`, fsyncs and renames on success (same as production
    /// reader). `--null` discards. `--hash` additionally SHA-256s everything received.
    pub fn open(a: &Args) -> Result<Self> {
        let file = match a.get("output") {
            Some(p) => {
                let dest = PathBuf::from(p);
                let part = dest.with_extension("part");
                let f =
                    File::create(&part).with_context(|| format!("creating {}", part.display()))?;
                Some((f, part, dest))
            }
            None if a.bool("null") => None,
            None => bail!("need --output PATH or --null"),
        };
        let hasher = a.bool("hash").then(Sha256::new);
        Ok(Self {
            file,
            hasher,
            bytes: 0,
        })
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some((f, _, _)) = &mut self.file {
            f.write_all(data)?;
        }
        if let Some(h) = &mut self.hasher {
            h.update(data);
        }
        self.bytes += data.len() as u64;
        Ok(())
    }

    /// Completes the transfer; returns the SHA-256 if hashing was requested.
    pub fn finish(self) -> Result<Option<String>> {
        if let Some((f, part, dest)) = self.file {
            f.sync_all()?;
            drop(f);
            fs::rename(&part, &dest)?;
        }
        Ok(self.hasher.map(|h| hex(&h.finalize())))
    }

    /// Discards a failed transfer, leaving any existing destination untouched.
    pub fn abort(self) {
        if let Some((f, part, _)) = self.file {
            drop(f);
            let _ = fs::remove_file(part);
        }
    }
}

/// Produces `[u32 len][frame]` records for the stream transports (UDS and staged files).
/// With crypto the frame is the production AES-256-GCM frame; without, it is the raw chunk
/// and a zero-length record marks end of stream.
pub struct FrameWriter {
    buf: Vec<u8>,
    chunk: usize,
    sealer: Option<Sealer>,
    done: bool,
}

impl FrameWriter {
    pub fn new(chunk: usize, sealer: Option<Sealer>) -> Self {
        Self {
            buf: vec![0u8; LEN_PREFIX + chunk + OVERHEAD],
            chunk,
            sealer,
            done: false,
        }
    }

    /// Returns the next encoded record, or `None` once the end-of-stream record was emitted.
    pub fn next_record(&mut self, src: &mut Source) -> Result<Option<&[u8]>> {
        if self.done {
            return Ok(None);
        }
        let (prefix, overhead) = if self.sealer.is_some() {
            (PREFIX_LEN, OVERHEAD)
        } else {
            (0, 0)
        };
        let body = LEN_PREFIX + prefix;
        let n = src.read_full(&mut self.buf[body..body + self.chunk])?;
        let last = n == 0;
        if let Some(s) = &mut self.sealer {
            s.seal_in_place(&mut self.buf[LEN_PREFIX..LEN_PREFIX + n + overhead], last)?;
        }
        let frame_len = n + overhead;
        self.buf[..LEN_PREFIX].copy_from_slice(&(frame_len as u32).to_le_bytes());
        self.done = last;
        Ok(Some(&self.buf[..LEN_PREFIX + frame_len]))
    }
}

/// Decodes records produced by [`FrameWriter`] from any byte stream.
pub struct FrameReader<R> {
    reader: R,
    buf: Vec<u8>,
    opener: Option<Opener>,
}

impl<R: Read> FrameReader<R> {
    pub fn new(reader: R, opener: Option<Opener>) -> Self {
        Self {
            reader,
            buf: Vec::new(),
            opener,
        }
    }

    /// Returns the next plaintext chunk, or `None` at the authenticated end of stream.
    pub fn next_chunk(&mut self) -> Result<Option<&[u8]>> {
        let mut len = [0u8; LEN_PREFIX];
        self.reader
            .read_exact(&mut len)
            .context("stream ended before end-of-stream frame")?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_FRAME {
            bail!("frame of {len} bytes exceeds limit");
        }
        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }
        self.reader
            .read_exact(&mut self.buf[..len])
            .context("truncated frame")?;
        match &mut self.opener {
            Some(o) => {
                let (plain, last) = o.open_in_place(&mut self.buf[..len])?;
                if last {
                    if !plain.is_empty() {
                        bail!("unexpected data in end-of-stream frame");
                    }
                    return Ok(None);
                }
                Ok(Some(plain))
            }
            None if len == 0 => Ok(None),
            None => Ok(Some(&self.buf[..len])),
        }
    }
}
