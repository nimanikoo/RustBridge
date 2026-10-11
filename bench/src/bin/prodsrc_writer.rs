use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use log::info;
use shared_ipc::crypto::{self, OVERHEAD, PREFIX_LEN, Sealer};
use shared_ipc::{DEFAULT_CHANNEL, DEFAULT_CHUNK_SIZE, DEFAULT_RING_SIZE, Producer};

/// Encrypts a file and streams it to a reader over POSIX shared memory.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// File to send.
    #[arg(default_value = "test_data/input.jpg")]
    input: PathBuf,

    /// Shared memory channel name (must start with '/', at most 31 bytes on macOS).
    #[arg(long, default_value = DEFAULT_CHANNEL)]
    channel: String,

    /// Ring buffer size in bytes (power of two).
    #[arg(long, default_value_t = DEFAULT_RING_SIZE)]
    ring_size: usize,

    /// Plaintext bytes per message.
    #[arg(long, default_value_t = DEFAULT_CHUNK_SIZE)]
    chunk_size: usize,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let key = crypto::key_from_env()?;
    let mut input =
        File::open(&args.input).with_context(|| format!("opening {}", args.input.display()))?;

    let mut producer = Producer::create(&args.channel, args.ring_size)
        .with_context(|| format!("creating shared memory channel {}", args.channel))?;
    ensure!(args.chunk_size > 0, "--chunk-size must be non-zero");
    ensure!(
        args.chunk_size + OVERHEAD <= producer.max_message_len(),
        "--chunk-size {} does not fit in a {} byte ring; use at most {}",
        args.chunk_size,
        args.ring_size,
        producer.max_message_len() - OVERHEAD
    );
    let mut sealer = Sealer::new(&key)?;
    info!(
        "channel {} ready ({} byte ring), sending {}",
        args.channel,
        args.ring_size,
        args.input.display()
    );

    let start = Instant::now();
    let mut sent: u64 = 0;
    loop {
        // Read the file straight into shared memory and encrypt it there: no intermediate buffers.
        let mut grant = producer.reserve(args.chunk_size + OVERHEAD)?;
        let n = read_full(
            &mut input,
            &mut grant[PREFIX_LEN..PREFIX_LEN + args.chunk_size],
        )?;
        if n == 0 {
            break;
        }
        sealer.seal_in_place(&mut grant[..n + OVERHEAD], false)?;
        grant.commit(n + OVERHEAD);
        sent += n as u64;
    }

    // An authenticated end-of-stream frame lets the reader detect truncation.
    let mut grant = producer.reserve(OVERHEAD)?;
    sealer.seal_in_place(&mut grant, true)?;
    grant.commit(OVERHEAD);

    info!("waiting for reader to consume the stream...");
    producer
        .wait_until_drained()
        .context("reader did not finish")?;

    let secs = start.elapsed().as_secs_f64();
    info!(
        "sent {sent} bytes in {:.3} ms ({:.1} MiB/s)",
        secs * 1e3,
        sent as f64 / (1 << 20) as f64 / secs
    );
    Ok(())
}

/// Fills `buf` from `reader`, returning fewer bytes only at end of file.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}
