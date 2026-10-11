//! Benchmark driver: launches independent processes, times them, verifies output, writes CSV.
//!
//!   driver gen       [--sizes LIST]                 generate payload files + manifest
//!   driver run       [--sizes LIST] [--configs LIST] [--reps N] [--warmup N] [--seed S] [--out CSV]
//!   driver aead      [--out CSV]                    AES-GCM micro-benchmark (hw + soft builds)
//!   driver summarize [--runs CSV] [--aead CSV]      statistics -> summary.csv / summary.md
//!
//! Timing boundaries (all CLOCK_MONOTONIC_RAW, nanoseconds):
//!   e2e      = driver timestamp just before spawning the first process  ->  after the last
//!              process has been reaped by wait4(2). Includes exec, dyld, setup, transfer,
//!              fsync/rename of the output, teardown. Excludes the SHA-256 verification.
//!   transfer = sender's first-byte timestamp -> receiver's completion timestamp (after
//!              fsync + rename). Only for `rbx` configs, which print both timestamps.
//!   sender   = sender's first-byte timestamp -> sender done (for shm: ring drained), i.e.
//!              the same boundary the production writer's "sent N bytes in X ms" log uses.
//!   startup  = e2e start -> sender's first-byte timestamp (spawn, exec, dyld, key/arg
//!              parsing, channel/socket setup, in-memory payload generation for mem configs).
//!   shutdown = receiver's completion timestamp -> receiver reaped (exit, unmap, teardown).
//!   prod_writer_internal / prod_reader_internal = parsed from production log lines.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use rustbridge_bench::*;

const DEFAULT_SIZES: &[usize] = &[4 << 10, 64 << 10, 1 << 20, 16 << 20, 256 << 20, 1 << 30];
const RUN_TIMEOUT: Duration = Duration::from_secs(180);

struct Paths {
    bench: PathBuf,
    work: PathBuf,
    data: PathBuf,
    results: PathBuf,
}

impl Paths {
    fn new() -> Self {
        let bench = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let work = bench.join("work");
        Self {
            data: work.join("data"),
            results: bench.join("results"),
            work,
            bench,
        }
    }
    fn repo(&self) -> PathBuf {
        self.bench.parent().unwrap().to_path_buf()
    }
    fn rbx(&self) -> PathBuf {
        self.bench.join("target/release/rbx")
    }
    fn rbx_soft(&self) -> PathBuf {
        self.work.join("target-soft-bench/release/rbx")
    }
    fn prod(&self, aes: &str, bin: &str) -> PathBuf {
        if aes == "hw-benchbuild" {
            self.bench
                .join("target/release")
                .join(format!("prodsrc_{bin}"))
        } else if aes == "soft" {
            self.work.join("target-soft/release").join(bin)
        } else {
            self.repo().join("target/release").join(bin)
        }
    }
    fn payload(&self, size: usize) -> PathBuf {
        self.data.join(format!("payload_{size}.bin"))
    }
}

// ------------------------------------------------------------------------- configurations

#[derive(Clone, Copy)]
struct Config {
    name: &'static str,
    /// "production" = unmodified writer/reader binaries; "experimental" = rbx.
    family: &'static str,
    transport: &'static str,
    crypto: bool,
    /// "hw" (ARMv8 AES/PMULL) or "soft" (RustCrypto constant-time fallback).
    aes: &'static str,
    /// "disk" source/sink = real files (warm page cache); "mem"/"null" = in-memory.
    source: &'static str,
    sink: &'static str,
    procs: u8,
    /// Restrict to these sizes (empty = all).
    only_sizes: &'static [usize],
}

const GIB_ONLY: &[usize] = &[1 << 30];
const LARGE: &[usize] = &[16 << 20, 256 << 20, 1 << 30];

const CONFIGS: &[Config] = &[
    Config {
        name: "prod-shm-aead",
        family: "production",
        transport: "shm-ring",
        crypto: true,
        aes: "hw",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "prod-shm-aead-softaes",
        family: "production",
        transport: "shm-ring",
        crypto: true,
        aes: "soft",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "exp-shm-aead",
        family: "experimental",
        transport: "shm-ring",
        crypto: true,
        aes: "hw",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "exp-shm-plain",
        family: "experimental",
        transport: "shm-ring",
        crypto: false,
        aes: "-",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "exp-uds-aead",
        family: "experimental",
        transport: "uds-4MiB",
        crypto: true,
        aes: "hw",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "exp-uds-plain",
        family: "experimental",
        transport: "uds-4MiB",
        crypto: false,
        aes: "-",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "exp-uds-aead-defaultbuf",
        family: "experimental",
        transport: "uds-default",
        crypto: true,
        aes: "hw",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: GIB_ONLY,
    },
    Config {
        name: "exp-file-aead",
        family: "experimental",
        transport: "staged-file",
        crypto: true,
        aes: "hw",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "exp-file-plain",
        family: "experimental",
        transport: "staged-file",
        crypto: false,
        aes: "-",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "exp-mmap-aead",
        family: "experimental",
        transport: "staged-mmap",
        crypto: true,
        aes: "hw",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "exp-mmap-plain",
        family: "experimental",
        transport: "staged-mmap",
        crypto: false,
        aes: "-",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: &[],
    },
    Config {
        name: "copy-aead",
        family: "experimental",
        transport: "none(1 proc)",
        crypto: true,
        aes: "hw",
        source: "disk",
        sink: "disk",
        procs: 1,
        only_sizes: &[],
    },
    Config {
        name: "copy-plain",
        family: "experimental",
        transport: "none(1 proc)",
        crypto: false,
        aes: "-",
        source: "disk",
        sink: "disk",
        procs: 1,
        only_sizes: &[],
    },
    Config {
        name: "mem-shm-aead",
        family: "experimental",
        transport: "shm-ring",
        crypto: true,
        aes: "hw",
        source: "mem",
        sink: "null",
        procs: 2,
        only_sizes: LARGE,
    },
    Config {
        name: "mem-shm-plain",
        family: "experimental",
        transport: "shm-ring",
        crypto: false,
        aes: "-",
        source: "mem",
        sink: "null",
        procs: 2,
        only_sizes: LARGE,
    },
    Config {
        name: "mem-uds-aead",
        family: "experimental",
        transport: "uds-4MiB",
        crypto: true,
        aes: "hw",
        source: "mem",
        sink: "null",
        procs: 2,
        only_sizes: LARGE,
    },
    Config {
        name: "mem-uds-plain",
        family: "experimental",
        transport: "uds-4MiB",
        crypto: false,
        aes: "-",
        source: "mem",
        sink: "null",
        procs: 2,
        only_sizes: LARGE,
    },
    Config {
        name: "spawn-baseline",
        family: "experimental",
        transport: "none(2 noop procs)",
        crypto: false,
        aes: "-",
        source: "-",
        sink: "-",
        procs: 2,
        only_sizes: &[0],
    },
    // Supplementary A/B (not part of the default campaign; select with --configs):
    // the unmodified production main.rs files compiled inside the bench crate.
    Config {
        name: "prodsrc-shm-aead",
        family: "production",
        transport: "shm-ring",
        crypto: true,
        aes: "hw-benchbuild",
        source: "disk",
        sink: "disk",
        procs: 2,
        only_sizes: GIB_ONLY,
    },
];

const UDS_TUNED_BUF: usize = 4 << 20;

struct RunCtx<'a> {
    p: &'a Paths,
    run_id: usize,
    size: usize,
    hash: bool,
}

impl RunCtx<'_> {
    fn out(&self) -> PathBuf {
        self.p
            .work
            .join("out")
            .join(format!("r{}.out", self.run_id))
    }
}

/// Returns the processes to launch, receiver first.
fn commands(cfg: &Config, ctx: &RunCtx) -> Vec<(&'static str, Command)> {
    let p = ctx.p;
    let id = ctx.run_id;
    let channel = format!("/rbb{}_{id}", std::process::id() % 100_000);
    let input = p.payload(ctx.size);
    let out = ctx.out();
    let crypto = if cfg.crypto { "1" } else { "0" };

    if cfg.family == "production" {
        let mut r = Command::new(p.prod(cfg.aes, "reader"));
        r.arg(&out).args(["--channel", &channel]);
        let mut w = Command::new(p.prod(cfg.aes, "writer"));
        w.arg(&input).args(["--channel", &channel]);
        return vec![("recv", r), ("send", w)];
    }
    if cfg.name == "spawn-baseline" {
        let mut a = Command::new(p.rbx());
        a.arg("noop");
        let mut b = Command::new(p.rbx());
        b.arg("noop");
        return vec![("recv", a), ("send", b)];
    }

    let rbx = p.rbx();
    let mut send_args: Vec<String> = vec!["--crypto".into(), crypto.into()];
    let mut recv_args: Vec<String> = vec!["--crypto".into(), crypto.into()];
    match cfg.source {
        "mem" => send_args.extend(["--mem".into(), ctx.size.to_string()]),
        _ => send_args.extend(["--input".into(), input.display().to_string()]),
    }
    match cfg.sink {
        "null" => {
            recv_args.push("--null".into());
            if ctx.hash {
                recv_args.push("--hash".into());
            }
        }
        _ => recv_args.extend(["--output".into(), out.display().to_string()]),
    }

    let (sub, extra): ((&str, &str), Vec<String>) = match cfg.transport {
        "shm-ring" => (("shm-send", "shm-recv"), vec!["--channel".into(), channel]),
        "uds-4MiB" | "uds-default" => {
            let sock = p
                .work
                .join("sock")
                .join(format!("r{id}.sock"))
                .display()
                .to_string();
            let buf = if cfg.transport == "uds-4MiB" {
                UDS_TUNED_BUF
            } else {
                0
            };
            (
                ("uds-send", "uds-recv"),
                vec!["--socket".into(), sock, "--sockbuf".into(), buf.to_string()],
            )
        }
        "staged-file" | "staged-mmap" => {
            let stage = p
                .work
                .join("stage")
                .join(format!("r{id}.stage"))
                .display()
                .to_string();
            let sub = if cfg.transport == "staged-file" {
                ("file-send", "file-recv")
            } else {
                ("mmap-send", "mmap-recv")
            };
            (sub, vec!["--staging".into(), stage])
        }
        _ => {
            // Single-process copy: one command carrying both source and sink arguments.
            let mut c = Command::new(&rbx);
            c.arg("copy").args(&send_args[2..]).args(&recv_args);
            return vec![("copy", c)];
        }
    };
    let mut r = Command::new(&rbx);
    r.arg(sub.1).args(&recv_args).args(&extra);
    let mut s = Command::new(&rbx);
    s.arg(sub.0).args(&send_args).args(&extra);
    vec![("recv", r), ("send", s)]
}

// ------------------------------------------------------------------------- process execution

#[derive(Default, Clone)]
struct ProcResult {
    role: String,
    exit_ns: u64,
    status: i32,
    utime_us: u64,
    stime_us: u64,
    maxrss: u64,
    stdout: String,
    stderr: String,
}

impl ProcResult {
    fn ok(&self) -> bool {
        libc::WIFEXITED(self.status) && libc::WEXITSTATUS(self.status) == 0
    }
    fn field(&self, key: &str) -> Option<u64> {
        let line = self.stdout.lines().find(|l| l.starts_with("RBX "))?;
        line.split_whitespace()
            .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
    }
    fn sfield(&self, key: &str) -> Option<String> {
        let line = self.stdout.lines().find(|l| l.starts_with("RBX "))?;
        line.split_whitespace()
            .find_map(|kv| Some(kv.strip_prefix(key)?.strip_prefix('=')?.to_string()))
    }
}

fn tv_us(tv: libc::timeval) -> u64 {
    tv.tv_sec as u64 * 1_000_000 + tv.tv_usec as u64
}

/// Spawns all commands (in order, back to back), reaps them with wait4(2) to collect
/// per-process rusage, and returns (t_spawn_ns, t_all_reaped_ns, results).
fn execute(cmds: Vec<(&'static str, Command)>, key: &str) -> Result<(u64, u64, Vec<ProcResult>)> {
    let mut children: Vec<(&str, Child)> = Vec::new();
    let t0 = now_ns();
    for (role, mut cmd) in cmds {
        cmd.env("RUSTBRIDGE_KEY", key)
            .env("RUST_LOG", "info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        children.push((
            role,
            cmd.spawn().with_context(|| format!("spawning {role}"))?,
        ));
    }

    // Drain pipes on threads so a chatty child can never block on a full pipe.
    let mut readers = Vec::new();
    let mut pids = HashMap::new();
    for (i, (role, child)) in children.iter_mut().enumerate() {
        pids.insert(child.id() as i32, i);
        let mut so = child.stdout.take().unwrap();
        let mut se = child.stderr.take().unwrap();
        readers.push((
            role.to_string(),
            std::thread::spawn(move || {
                let mut s = String::new();
                let _ = so.read_to_string(&mut s);
                s
            }),
            std::thread::spawn(move || {
                let mut s = String::new();
                let _ = se.read_to_string(&mut s);
                s
            }),
        ));
    }

    // Watchdog: kill everything if the run exceeds RUN_TIMEOUT.
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let kill_list: Vec<i32> = pids.keys().copied().collect();
    let watchdog = std::thread::spawn(move || {
        if done_rx.recv_timeout(RUN_TIMEOUT).is_err() {
            for pid in kill_list {
                // SAFETY: plain kill(2) on our own children.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            return true;
        }
        false
    });

    let mut results = vec![ProcResult::default(); children.len()];
    let mut remaining = children.len();
    while remaining > 0 {
        let mut status = 0;
        // SAFETY: zeroed rusage is a valid out-parameter.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        let pid = unsafe { libc::wait4(-1, &mut status, 0, &mut ru) };
        let t = now_ns();
        if pid < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            bail!("wait4: {err}");
        }
        if let Some(&i) = pids.get(&pid) {
            results[i] = ProcResult {
                role: children[i].0.to_string(),
                exit_ns: t,
                status,
                utime_us: tv_us(ru.ru_utime),
                stime_us: tv_us(ru.ru_stime),
                maxrss: ru.ru_maxrss as u64, // bytes on macOS
                ..Default::default()
            };
            remaining -= 1;
        }
    }
    let t_end = now_ns();
    let _ = done_tx.send(());
    let timed_out = watchdog.join().unwrap_or(false);

    for (i, (_, so, se)) in readers.into_iter().enumerate() {
        results[i].stdout = so.join().unwrap_or_default();
        results[i].stderr = se.join().unwrap_or_default();
        if timed_out {
            results[i]
                .stderr
                .push_str("\n[driver] killed by watchdog timeout");
        }
    }
    // The children were reaped via wait4; forget the handles so std does not wait again.
    for (_, c) in children {
        std::mem::forget(c);
    }
    Ok((t0, t_end, results))
}

/// Parses "<verb> N bytes in X ms" from a production log line.
fn parse_prod_ms(stderr: &str, verb: &str) -> Option<f64> {
    let line = stderr.lines().find(|l| l.contains(&format!("] {verb} ")))?;
    let rest = line.split("bytes in ").nth(1)?;
    rest.split(" ms").next()?.trim().parse().ok()
}

// ------------------------------------------------------------------------- run command

const CSV_HEADER: &str = "run_id,kind,order,unix_time,config,family,transport,crypto,aes,source,sink,procs,size_bytes,\
e2e_ns,transfer_ns,sender_ns,startup_ns,shutdown_ns,prod_writer_internal_ns,prod_reader_internal_ns,\
send_utime_us,send_stime_us,send_maxrss_bytes,recv_utime_us,recv_stime_us,recv_maxrss_bytes,\
cpu_total_us,exit_ok,verified,note";

fn load_manifest(p: &Paths) -> Result<HashMap<usize, String>> {
    let text = fs::read_to_string(p.data.join("manifest.csv")).context("run `driver gen` first")?;
    Ok(text
        .lines()
        .skip(1)
        .filter_map(|l| {
            let mut it = l.split(',');
            Some((it.next()?.parse().ok()?, it.next()?.to_string()))
        })
        .collect())
}

fn parse_sizes(a: &Args) -> Result<Vec<usize>> {
    match a.get("sizes") {
        Some(s) => s
            .split(',')
            .map(|x| x.parse().context("bad --sizes"))
            .collect(),
        None => Ok(DEFAULT_SIZES.to_vec()),
    }
}

fn shuffle<T>(v: &mut [T], seed: &mut u64) {
    for i in (1..v.len()).rev() {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = ((*seed >> 33) as usize) % (i + 1);
        v.swap(i, j);
    }
}

fn cmd_gen(a: &Args, p: &Paths) -> Result<()> {
    fs::create_dir_all(&p.data)?;
    let mut manifest = String::from("size_bytes,sha256,path\n");
    let mut sizes = parse_sizes(a)?;
    sizes.extend([0, 1000003]); // empty and non-chunk-multiple payloads for correctness checks
    sizes.sort();
    sizes.dedup();
    for size in sizes {
        let path = p.payload(size);
        let mut f = File::create(&path)?;
        let mut buf = vec![0u8; 1 << 20];
        let mut off = 0usize;
        while off < size {
            let n = (size - off).min(buf.len());
            fill_payload(off as u64, &mut buf[..n]);
            f.write_all(&buf[..n])?;
            off += n;
        }
        f.sync_all()?;
        let h = sha256_file(&path)?;
        println!("generated {} ({size} bytes) sha256={h}", path.display());
        writeln!(manifest, "{size},{h},{}", path.display())?;
    }
    fs::write(p.data.join("manifest.csv"), manifest)?;
    Ok(())
}

fn cmd_run(a: &Args, p: &Paths) -> Result<()> {
    let sizes = parse_sizes(a)?;
    let reps = a.num("reps", 10)?;
    let warmup = a.num("warmup", 1)?;
    let mut seed = a.num("seed", 20261011)? as u64;
    let selected: Option<Vec<&str>> = a.get("configs").map(|s| s.split(',').collect());
    let out_path = PathBuf::from(
        a.get("out")
            .map(String::from)
            .unwrap_or_else(|| p.results.join("runs.csv").display().to_string()),
    );
    let manifest = load_manifest(p)?;
    for d in ["out", "sock", "stage"] {
        fs::create_dir_all(p.work.join(d))?;
    }
    let key = {
        let mut k = [0u8; 32];
        fill_payload(1 << 40, &mut k);
        hex(&k)
    };

    // Build the plan: (config, size, kind) entries. Warm-ups first, then measured runs in a
    // seeded random order across all configs and sizes, then untimed hash-verification runs.
    let mut pairs = Vec::new();
    for cfg in CONFIGS {
        let supplementary = cfg.name.starts_with("prodsrc-");
        match &selected {
            Some(s) if !s.contains(&cfg.name) => continue,
            None if supplementary => continue,
            _ => {}
        }
        let cfg_sizes: Vec<usize> = if cfg.only_sizes.is_empty() {
            sizes.clone()
        } else {
            cfg.only_sizes
                .iter()
                .copied()
                .filter(|s| *s == 0 || sizes.contains(s))
                .collect()
        };
        for s in cfg_sizes {
            pairs.push((*cfg, s));
        }
    }
    let mut warm: Vec<_> = pairs
        .iter()
        .flat_map(|&(c, s)| std::iter::repeat_n((c, s, "warmup"), warmup))
        .collect();
    let mut measured: Vec<_> = pairs
        .iter()
        .flat_map(|&(c, s)| std::iter::repeat_n((c, s, "measured"), reps))
        .collect();
    shuffle(&mut warm, &mut seed);
    shuffle(&mut measured, &mut seed);
    let verify: Vec<_> = pairs
        .iter()
        .filter(|(c, _)| c.sink == "null")
        .map(|&(c, s)| (c, s, "verify"))
        .collect();
    let plan: Vec<_> = warm.into_iter().chain(measured).chain(verify).collect();

    // Warm the page cache for every source file used (cold cache cannot be established
    // without `sudo purge`, which this suite deliberately does not use).
    for &s in &sizes {
        if s > 0 {
            let _ = sha256_file(&p.payload(s))?;
        }
    }

    let append = out_path.exists() && a.bool("append");
    let mut csv = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(&out_path)?;
    if !append {
        writeln!(csv, "{CSV_HEADER}")?;
    }
    let total = plan.len();
    let mut failures = 0;
    let base_id = a.num("first-id", 0)?;
    for (order, (cfg, size, kind)) in plan.into_iter().enumerate() {
        let run_id = base_id + order;
        let ctx = RunCtx {
            p,
            run_id,
            size,
            hash: kind == "verify",
        };
        let (t0, t1, res) = execute(commands(&cfg, &ctx), &key)?;
        let send = res
            .iter()
            .find(|r| r.role == "send" || r.role == "copy")
            .cloned()
            .unwrap_or_default();
        let recv = res
            .iter()
            .find(|r| r.role == "recv" || r.role == "copy")
            .cloned()
            .unwrap_or_default();
        let exit_ok = res.iter().all(ProcResult::ok);

        // Verification (outside the timed region).
        let expected = manifest.get(&size).cloned().unwrap_or_default();
        let (verified, mut note) = if cfg.name == "spawn-baseline" {
            ("n/a".to_string(), String::new())
        } else if cfg.sink == "null" {
            if kind == "verify" {
                let got = recv.sfield("sha256").unwrap_or_default();
                (
                    (got == expected).to_string(),
                    "receiver-side sha256".to_string(),
                )
            } else {
                ("by-verify-run".to_string(), String::new())
            }
        } else {
            let out = ctx.out();
            let v = match sha256_file(&out) {
                Ok(h) => (h == expected).to_string(),
                Err(_) => "false".to_string(),
            };
            let _ = fs::remove_file(&out);
            (v, String::new())
        };
        if !exit_ok || verified == "false" {
            failures += 1;
            let errs: Vec<String> = res
                .iter()
                .map(|r| format!("{}:{}", r.role, r.stderr.trim().replace(['\n', ','], " | ")))
                .collect();
            note = format!("FAILED {}", errs.join(" ; "))
                .chars()
                .take(400)
                .collect();
        }

        let transfer = match (send.field("t_start"), recv.field("t_end")) {
            (Some(a), Some(b)) if b >= a => (b - a).to_string(),
            _ => String::new(),
        };
        let sender = match (send.field("t_start"), send.field("t_end")) {
            (Some(a), Some(b)) => (b - a).to_string(),
            _ => String::new(),
        };
        let startup = send
            .field("t_start")
            .filter(|&s| s >= t0)
            .map(|s| (s - t0).to_string())
            .unwrap_or_default();
        let shutdown = recv
            .field("t_end")
            .filter(|&e| recv.exit_ns >= e)
            .map(|e| (recv.exit_ns - e).to_string())
            .unwrap_or_default();
        let ms_to_ns = |v: Option<f64>| {
            v.map(|ms| ((ms * 1e6) as u64).to_string())
                .unwrap_or_default()
        };
        let pw = ms_to_ns(parse_prod_ms(&send.stderr, "sent"));
        let pr = ms_to_ns(parse_prod_ms(&recv.stderr, "received"));
        let single = cfg.procs == 1;
        let cpu = if single {
            send.utime_us + send.stime_us
        } else {
            send.utime_us + send.stime_us + recv.utime_us + recv.stime_us
        };
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        writeln!(
            csv,
            "{run_id},{kind},{order},{unix},{},{},{},{},{},{},{},{},{size},{},{transfer},{sender},{startup},{shutdown},{pw},{pr},{},{},{},{},{},{},{cpu},{exit_ok},{verified},{note}",
            cfg.name,
            cfg.family,
            cfg.transport,
            cfg.crypto,
            cfg.aes,
            cfg.source,
            cfg.sink,
            cfg.procs,
            t1 - t0,
            send.utime_us,
            send.stime_us,
            send.maxrss,
            if single { 0 } else { recv.utime_us },
            if single { 0 } else { recv.stime_us },
            if single { 0 } else { recv.maxrss },
        )?;
        csv.flush()?;
        eprintln!(
            "[{:>4}/{total}] {kind:<8} {:<26} {:>10} B  e2e {:>9.3} ms  ok={exit_ok} verified={verified}",
            order + 1,
            cfg.name,
            size,
            (t1 - t0) as f64 / 1e6
        );
    }
    eprintln!(
        "done: {total} runs, {failures} failures -> {}",
        out_path.display()
    );
    Ok(())
}

// ------------------------------------------------------------------------- aead command

fn cmd_aead(a: &Args, p: &Paths) -> Result<()> {
    let out_path = PathBuf::from(
        a.get("out")
            .map(String::from)
            .unwrap_or_else(|| p.results.join("aead.csv").display().to_string()),
    );
    let sizes = parse_sizes(a)?;
    let mut csv = File::create(&out_path)?;
    writeln!(
        csv,
        "build,chunk_bytes,size_bytes,rep,seal_ns,open_ns,verified"
    )?;
    let mut jobs: Vec<(&str, PathBuf, usize, usize, usize)> = Vec::new();
    for &chunk in &[4 << 10, 64 << 10, 256 << 10, 1 << 20] {
        for &size in &sizes {
            jobs.push(("hw", p.rbx(), chunk, size, 10));
        }
    }
    // Software AES is ~8x slower; measure it at the production chunk size only.
    for &size in &sizes {
        jobs.push((
            "soft",
            p.rbx_soft(),
            256 << 10,
            size,
            if size >= 1 << 30 { 5 } else { 10 },
        ));
    }
    for (build, bin, chunk, size, reps) in jobs {
        let out = Command::new(&bin)
            .args([
                "aead",
                "--chunk",
                &chunk.to_string(),
                "--size",
                &size.to_string(),
                "--reps",
                &reps.to_string(),
            ])
            .output()
            .with_context(|| format!("running {}", bin.display()))?;
        ensure!(
            out.status.success(),
            "aead failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            writeln!(csv, "{build},{line}")?;
        }
        eprintln!("aead {build} chunk={chunk} size={size} reps={reps} done");
    }
    Ok(())
}

// ------------------------------------------------------------------------- summarize command

#[derive(Default)]
struct Stats {
    n: usize,
    median: f64,
    min: f64,
    max: f64,
    mean: f64,
    stdev: f64,
    p95: Option<f64>,
}

fn stats(mut v: Vec<f64>) -> Stats {
    if v.is_empty() {
        return Stats::default();
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    let median = if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    };
    let mean = v.iter().sum::<f64>() / n as f64;
    let stdev = if n > 1 {
        (v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64).sqrt()
    } else {
        0.0
    };
    // Nearest-rank p95, reported only when there are at least 10 samples.
    let p95 = (n >= 10).then(|| v[((0.95 * n as f64).ceil() as usize).clamp(1, n) - 1]);
    Stats {
        n,
        median,
        min: v[0],
        max: v[n - 1],
        mean,
        stdev,
        p95,
    }
}

type Row = HashMap<String, String>;

fn read_csv(path: &Path) -> Result<Vec<Row>> {
    let f =
        BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
    let mut lines = f.lines();
    let header: Vec<String> = lines
        .next()
        .context("empty csv")??
        .split(',')
        .map(String::from)
        .collect();
    let mut rows = Vec::new();
    for line in lines {
        let line = line?;
        // `note` is the last column and may itself contain commas.
        let cols: Vec<&str> = line.splitn(header.len(), ',').collect();
        rows.push(
            header
                .iter()
                .cloned()
                .zip(cols.iter().map(|s| s.to_string()))
                .collect(),
        );
    }
    Ok(rows)
}

fn fmt_size(b: usize) -> String {
    match b {
        0 => "0".into(),
        b if b >= 1 << 30 => format!("{} GiB", b >> 30),
        b if b >= 1 << 20 => format!("{} MiB", b >> 20),
        b => format!("{} KiB", b >> 10),
    }
}

fn cmd_summarize(a: &Args, p: &Paths) -> Result<()> {
    let runs_path = a
        .get("runs")
        .map(PathBuf::from)
        .unwrap_or_else(|| p.results.join("runs.csv"));
    let rows = read_csv(&runs_path)?;
    let mut groups: BTreeMap<(usize, String), Vec<&HashMap<String, String>>> = BTreeMap::new();
    let mut meta: HashMap<String, &HashMap<String, String>> = HashMap::new();
    let mut failed: BTreeMap<(usize, String), usize> = BTreeMap::new();
    let mut verify: BTreeMap<(usize, String), String> = BTreeMap::new();
    for r in &rows {
        let size: usize = r["size_bytes"].parse()?;
        let key = (size, r["config"].clone());
        meta.entry(r["config"].clone()).or_insert(r);
        match r["kind"].as_str() {
            "measured" => {
                if r["exit_ok"] == "true" && r["verified"] != "false" {
                    groups.entry(key).or_default().push(r);
                } else {
                    *failed.entry(key).or_default() += 1;
                }
            }
            "verify" => {
                verify.insert(key, r["verified"].clone());
            }
            _ => {}
        }
    }

    let col = |rs: &[&HashMap<String, String>], c: &str| -> Vec<f64> {
        rs.iter().filter_map(|r| r[c].parse::<f64>().ok()).collect()
    };
    let mut csv = String::from(
        "config,family,transport,crypto,aes,source,sink,size_bytes,n,failed,e2e_median_ms,e2e_min_ms,e2e_max_ms,e2e_mean_ms,e2e_stdev_ms,e2e_cv_pct,e2e_p95_ms,\
e2e_throughput_mib_s,e2e_throughput_gib_s,transfer_median_ms,transfer_min_ms,transfer_max_ms,transfer_throughput_mib_s,sender_median_ms,\
startup_median_ms,shutdown_median_ms,prod_writer_internal_median_ms,prod_writer_internal_min_ms,prod_writer_internal_max_ms,prod_reader_internal_median_ms,\
cpu_total_median_ms,cpu_util_median_pct,send_maxrss_median_mib,recv_maxrss_median_mib,first_half_median_ms,second_half_median_ms,verified\n",
    );
    let mut md = String::new();
    let mut by_size: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for ((size, name), rs) in &groups {
        let m = meta[name];
        let e2e = stats(col(rs, "e2e_ns").iter().map(|x| x / 1e6).collect());
        let tr = stats(col(rs, "transfer_ns").iter().map(|x| x / 1e6).collect());
        let snd = stats(col(rs, "sender_ns").iter().map(|x| x / 1e6).collect());
        let su = stats(col(rs, "startup_ns").iter().map(|x| x / 1e6).collect());
        let sd = stats(col(rs, "shutdown_ns").iter().map(|x| x / 1e6).collect());
        let pw = stats(
            col(rs, "prod_writer_internal_ns")
                .iter()
                .map(|x| x / 1e6)
                .collect(),
        );
        let pr = stats(
            col(rs, "prod_reader_internal_ns")
                .iter()
                .map(|x| x / 1e6)
                .collect(),
        );
        let cpu = stats(col(rs, "cpu_total_us").iter().map(|x| x / 1e3).collect());
        let util = stats(
            rs.iter()
                .filter_map(|r| {
                    Some(
                        r["cpu_total_us"].parse::<f64>().ok()?
                            / (r["e2e_ns"].parse::<f64>().ok()? / 1e3)
                            * 100.0,
                    )
                })
                .collect(),
        );
        let srss = stats(
            col(rs, "send_maxrss_bytes")
                .iter()
                .map(|x| x / (1u64 << 20) as f64)
                .collect(),
        );
        let rrss = stats(
            col(rs, "recv_maxrss_bytes")
                .iter()
                .map(|x| x / (1u64 << 20) as f64)
                .collect(),
        );
        // Drift check: medians of the first and second half of repetitions in execution order.
        let mut ordered: Vec<(usize, f64)> = rs
            .iter()
            .filter_map(|r| {
                Some((
                    r["order"].parse().ok()?,
                    r["e2e_ns"].parse::<f64>().ok()? / 1e6,
                ))
            })
            .collect();
        ordered.sort_by_key(|x| x.0);
        let half = ordered.len() / 2;
        let h1 = stats(ordered[..half].iter().map(|x| x.1).collect());
        let h2 = stats(ordered[half..].iter().map(|x| x.1).collect());
        let mib = *size as f64 / (1u64 << 20) as f64;
        let thr = |ms: f64| {
            if ms > 0.0 && *size > 0 {
                mib / (ms / 1e3)
            } else {
                0.0
            }
        };
        let opt = |s: &Stats| {
            if s.n > 0 {
                format!("{:.3}", s.median)
            } else {
                String::new()
            }
        };
        let ver = if m["sink"] == "null" {
            verify
                .get(&(*size, name.clone()))
                .cloned()
                .unwrap_or("not-run".into())
        } else if name == "spawn-baseline" {
            "n/a".into()
        } else {
            "all-runs".into()
        };
        let nfail = failed.get(&(*size, name.clone())).copied().unwrap_or(0);
        writeln!(
            csv,
            "{name},{},{},{},{},{},{},{size},{},{nfail},{:.3},{:.3},{:.3},{:.3},{:.3},{:.2},{},{:.1},{:.3},{},{},{},{},{},{},{},{},{},{},{},{:.1},{:.0},{:.1},{:.1},{:.3},{:.3},{ver}",
            m["family"],
            m["transport"],
            m["crypto"],
            m["aes"],
            m["source"],
            m["sink"],
            e2e.n,
            e2e.median,
            e2e.min,
            e2e.max,
            e2e.mean,
            e2e.stdev,
            if e2e.mean > 0.0 {
                e2e.stdev / e2e.mean * 100.0
            } else {
                0.0
            },
            e2e.p95.map(|v| format!("{v:.3}")).unwrap_or_default(),
            thr(e2e.median),
            thr(e2e.median) / 1024.0,
            opt(&tr),
            if tr.n > 0 {
                format!("{:.3}", tr.min)
            } else {
                String::new()
            },
            if tr.n > 0 {
                format!("{:.3}", tr.max)
            } else {
                String::new()
            },
            if tr.n > 0 {
                format!("{:.1}", thr(tr.median))
            } else {
                String::new()
            },
            opt(&snd),
            opt(&su),
            opt(&sd),
            opt(&pw),
            if pw.n > 0 {
                format!("{:.3}", pw.min)
            } else {
                String::new()
            },
            if pw.n > 0 {
                format!("{:.3}", pw.max)
            } else {
                String::new()
            },
            opt(&pr),
            cpu.median,
            util.median,
            srss.median,
            rrss.median,
            h1.median,
            h2.median,
        )?;
        let transfer_col = if tr.n > 0 {
            format!("{:.2} ({:.0} MiB/s)", tr.median, thr(tr.median))
        } else if pr.n > 0 {
            format!("{:.2}* ({:.0} MiB/s)", pr.median, thr(pr.median))
        } else {
            "—".into()
        };
        by_size.entry(*size).or_default().push(format!(
            "| {name} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {} | {:.1}% | {} | {transfer_col} | {:.0} | {:.0}% | {:.1} / {:.1} | {ver} |",
            e2e.n,
            if *size > 0 { format!("{:.0}", thr(e2e.median)) } else { "—".into() },
            if *size > 0 { format!("{:.3}", thr(e2e.median) / 1024.0) } else { "—".into() },
            e2e.median, e2e.min, e2e.max,
            e2e.p95.map(|v| format!("{v:.2}")).unwrap_or("—".into()),
            if e2e.mean > 0.0 { e2e.stdev / e2e.mean * 100.0 } else { 0.0 },
            nfail,
            cpu.median, util.median, srss.median, rrss.median,
        ));
    }
    for (size, lines) in &by_size {
        writeln!(md, "\n### Payload {}\n", fmt_size(*size))?;
        md.push_str("| config | n | e2e MiB/s | e2e GiB/s | e2e median ms | min ms | max ms | p95 ms | CV | failed | transfer median ms (MiB/s) | CPU ms | CPU util | peak RSS MiB send / recv | verified |\n");
        md.push_str("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
        for l in lines {
            md.push_str(l);
            md.push('\n');
        }
    }
    fs::write(p.results.join("summary.csv"), csv)?;

    // AEAD micro-benchmark summary.
    let aead_path = a
        .get("aead")
        .map(PathBuf::from)
        .unwrap_or_else(|| p.results.join("aead.csv"));
    if aead_path.exists() {
        let rows = read_csv(&aead_path)?;
        let mut g: BTreeMap<(String, usize, usize), Vec<&Row>> = BTreeMap::new();
        for r in &rows {
            g.entry((
                r["build"].clone(),
                r["chunk_bytes"].parse()?,
                r["size_bytes"].parse()?,
            ))
            .or_default()
            .push(r);
        }
        let mut acsv = String::from(
            "build,chunk_bytes,size_bytes,n,seal_median_ms,seal_min_ms,seal_max_ms,seal_median_mib_s,open_median_ms,open_min_ms,open_max_ms,open_median_mib_s,all_verified\n",
        );
        writeln!(
            md,
            "\n### AES-256-GCM micro-benchmark (in-process, in-memory)\n"
        )?;
        md.push_str("| build | chunk | payload | n | seal median ms | seal MiB/s (median) | seal min–max ms | open median ms | open MiB/s (median) | open min–max ms | verified |\n|---|---|---|---|---|---|---|---|---|---|---|\n");
        for ((build, chunk, size), rs) in &g {
            let s = stats(col(rs, "seal_ns").iter().map(|x| x / 1e6).collect());
            let o = stats(col(rs, "open_ns").iter().map(|x| x / 1e6).collect());
            let mib = *size as f64 / (1u64 << 20) as f64;
            let ok = rs.iter().all(|r| r["verified"] == "true");
            writeln!(
                acsv,
                "{build},{chunk},{size},{},{:.4},{:.4},{:.4},{:.1},{:.4},{:.4},{:.4},{:.1},{ok}",
                s.n,
                s.median,
                s.min,
                s.max,
                mib / (s.median / 1e3),
                o.median,
                o.min,
                o.max,
                mib / (o.median / 1e3)
            )?;
            writeln!(
                md,
                "| {build} | {} | {} | {} | {:.3} | {:.0} | {:.3}–{:.3} | {:.3} | {:.0} | {:.3}–{:.3} | {ok} |",
                fmt_size(*chunk),
                fmt_size(*size),
                s.n,
                s.median,
                mib / (s.median / 1e3),
                s.min,
                s.max,
                o.median,
                mib / (o.median / 1e3),
                o.min,
                o.max
            )?;
        }
        fs::write(p.results.join("aead_summary.csv"), acsv)?;
    }
    fs::write(p.results.join("summary.md"), md)?;
    eprintln!(
        "wrote summary.csv, summary.md{}",
        if aead_path.exists() {
            ", aead_summary.csv"
        } else {
            ""
        }
    );
    Ok(())
}

fn main() -> Result<()> {
    let mut argv = std::env::args().skip(1);
    let cmd = argv.next().unwrap_or_default();
    let a = Args::parse(argv)?;
    let p = Paths::new();
    fs::create_dir_all(&p.results)?;
    match cmd.as_str() {
        "gen" => cmd_gen(&a, &p),
        "run" => cmd_run(&a, &p),
        "aead" => cmd_aead(&a, &p),
        "summarize" => cmd_summarize(&a, &p),
        _ => bail!("usage: driver gen|run|aead|summarize [options]"),
    }
}
