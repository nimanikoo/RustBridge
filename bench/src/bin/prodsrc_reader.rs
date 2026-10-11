use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use log::info;
use shared_ipc::crypto::{self, Opener};
use shared_ipc::{Consumer, DEFAULT_CHANNEL};

/// Receives an encrypted stream over POSIX shared memory and writes the decrypted file.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Where to write the decrypted file.
    #[arg(default_value = "test_data/output.jpg")]
    output: PathBuf,

    /// Shared memory channel name (must match the writer).
    #[arg(long, default_value = DEFAULT_CHANNEL)]
    channel: String,

    /// Seconds to wait for the writer to create the channel.
    #[arg(long, default_value_t = 30)]
    timeout: u64,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let key = crypto::key_from_env()?;
    let mut opener = Opener::new(&key);

    info!("waiting for writer on channel {}...", args.channel);
    let mut consumer = Consumer::connect(&args.channel, Duration::from_secs(args.timeout))
        .with_context(|| format!("attaching to shared memory channel {}", args.channel))?;
    info!("attached to {}", args.channel);

    if let Some(dir) = args.output.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    // Write to a temporary file and rename on success, so a failed transfer never
    // leaves a truncated or unauthenticated file at the destination.
    let partial = args.output.with_extension("part");
    let mut out =
        File::create(&partial).with_context(|| format!("creating {}", partial.display()))?;

    let start = Instant::now();
    let mut received: u64 = 0;
    let result: Result<()> = loop {
        let mut msg = match consumer.recv() {
            Ok(msg) => msg,
            Err(e) => break Err(e).context("writer disconnected before end of stream"),
        };
        let (plaintext, last) = match opener.open_in_place(&mut msg) {
            Ok(frame) => frame,
            Err(e) => break Err(e.into()),
        };
        if last {
            if !plaintext.is_empty() {
                break Err(anyhow::anyhow!("unexpected data in end-of-stream frame"));
            }
            break Ok(());
        }
        // Decrypted in place in shared memory; written out without another copy.
        if let Err(e) = out.write_all(plaintext) {
            break Err(e.into());
        }
        received += plaintext.len() as u64;
    };

    if let Err(e) = result {
        drop(out);
        let _ = fs::remove_file(&partial);
        bail!(e);
    }
    out.sync_all()?;
    fs::rename(&partial, &args.output)?;

    let secs = start.elapsed().as_secs_f64();
    info!(
        "received {received} bytes in {:.3} ms ({:.1} MiB/s) -> {}",
        secs * 1e3,
        received as f64 / (1 << 20) as f64 / secs,
        args.output.display()
    );
    Ok(())
}
