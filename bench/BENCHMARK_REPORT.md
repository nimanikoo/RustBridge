# RustBridge Benchmark Report

**Question:** Can the reported figure of *0.68 s for an end-to-end 1 GiB encrypted transfer on an Apple M4 Mac*
be reproduced, and how does the shared-memory implementation compare with other ways of moving the
same bytes between two processes?

**Short answer:**

- **The 0.68 s figure reproduces in a warm page cache.** Measured as the wall-clock time of two
  independently launched processes, it is **659 ms median** (651–888 ms, n=10). The production
  writer's internal timer, which is what the original figure was based on, gives **648 ms median**.
- **The 5.1 s software-AES figure also reproduces:** 5059 ms median (5007–5122 ms, n=10).
- **At 1 GiB from disk to disk, transfer speed is limited by file I/O, not by IPC.** Shared memory,
  a Unix domain socket with enlarged buffers, and a single-process plain file copy all finish in
  about 560–585 ms.
- **The production binaries are ~13% slower than an experimental program that runs the same data path**
  (659 vs 581 ms), because they spend ~25% more user-mode CPU per process.
- **At small payloads the shared-memory transport is the slowest option** (~16–17 ms vs ~7 ms), most
  likely because of a 10 ms retry sleep when the reader connects.

All numbers below are measurements from this campaign unless explicitly marked *historical* or
*hypothesis*.

---

## 1. What was benchmarked

### 1.1 Existing implementation (production, unmodified)

`writer` / `reader` as committed in `51eafb4`. The binaries were built at 18:57 UTC from the working tree,
nine minutes before that commit was made. `results/environment.txt` therefore still shows "`b8fffce` +
uncommitted changes". The production sources were last modified at 18:27 UTC and are byte-identical to
`51eafb4`, and the binary hashes in `results/build_info.txt` were unchanged after the campaign. The data path:

```
writer: read(2) source file ──► directly into a reserved ring slot (shared memory)
        AES-256-GCM seal in place (13 B prefix + 16 B tag per 256 KiB chunk)
        Release-store of head ─────────────────────────────────────────────┐
reader: Acquire-load of head ◄─────────────────────────────────────────────┘
        bounds check, AES-256-GCM open in place in shared memory
        write(2) plaintext to <out>.part; after the authenticated end-of-stream frame: fsync, rename
writer: waits until tail == head (ring drained), unlinks the segment, exits
```

| Parameter | Value |
|---|---|
| Shared memory | `shm_open` + `ftruncate` + `mmap(MAP_SHARED)`, mode 0600 |
| Ring | 4 MiB data area (power of two) + 192 B header; `head`/`tail` on separate 64 B-aligned lines |
| Chunk | 256 KiB plaintext per message (frame = chunk + 29 B) |
| Synchronisation | Lock-free SPSC; waiting = 64 spins → 64 `sched_yield` → `nanosleep(50 µs)` loop; peer PID liveness check every 1024 waits |
| Reader attach | `Consumer::connect` retries `shm_open` every **10 ms** until the segment exists |
| Crypto | RustCrypto `aes-gcm 0.10.3` (`aes 0.8.4`, `polyval 0.6.2`), ARMv8 AES + PMULL enabled with `--cfg aes_armv8 --cfg polyval_armv8` in `.cargo/config.toml` |
| Output durability | `File::sync_all` (`fsync(2)`, **not** `F_FULLFSYNC`) then `rename(2)` |

Hardware acceleration was checked at the instruction level, not assumed. `otool -tv` finds
`aese`/`aesmc`/`pmull` instructions in the hardware builds and none in the software builds
(`results/build_info.txt`).

### 1.2 Experimental implementations (new, `bench/src/bin/rbx.rs`)

Every experimental transport uses the production `shared_ipc` crate (`Sealer`/`Opener` and, for
shared memory, `Producer`/`Consumer`) unchanged. Every two-process test launches **two
independent OS processes**. No in-process substitute is used for an IPC test.

| Config | Processes | Transport | Copies of each payload byte (user↔kernel) | Pipelined? | Notes |
|---|---|---|---|---|---|
| `prod-shm-aead` | 2 | shared memory ring | read: kernel→ring; write: ring→kernel | yes (4 MiB ring) | **production binaries** |
| `prod-shm-aead-softaes` | 2 | same | same | yes | same source, `--cfg aes_force_soft --cfg polyval_force_soft` |
| `exp-shm-aead` / `-plain` | 2 | production ring | same as production | yes | re-implementation of the production loop in `rbx` |
| `exp-uds-aead` / `-plain` | 2 | `AF_UNIX` stream socket, `SO_SNDBUF`/`SO_RCVBUF` = 4 MiB (effective value is recorded) | read→user buf, write→socket (copy), socket→user buf (copy), write→kernel | yes | same AES-GCM frames, 4 B length prefix |
| `exp-uds-aead-defaultbuf` | 2 | same, **macOS default 8 KiB** socket buffers | same | yes | 1 GiB only |
| `exp-file-aead` / `-plain` | 2 | staging file: sender writes the whole framed stream, `rename` publishes it, receiver polls every 1 ms | +1 write and +1 read of a staging file (page cache, no fsync) | **no** (sequential) | needs payload-sized staging space |
| `exp-mmap-aead` / `-plain` | 2 | staging file accessed via `mmap`: sender `MAP_SHARED` (read source straight into the map, seal in place); receiver `MAP_PRIVATE` (decrypt in place without writing back) | page-cache mapping instead of read/write; copy-on-write faults on the receiver | **no** | needs payload-sized staging space |
| `copy-aead` / `-plain` | **1** | none: read → (seal → open) → write in one process | same as a plain copy | n/a | **file-based baseline**: the floor for disk→disk |
| `mem-*-aead` / `-plain` | 2 | shm or UDS | sender's source is a payload generated in memory before timing starts; receiver discards (`--null`) | yes | isolates IPC + crypto from file I/O (see 1.4) |
| `spawn-baseline` | 2 | none | — | — | two `rbx noop` processes: spawn/exec/exit cost |
| `prodsrc-shm-aead` | 2 | production ring | as production | yes | supplementary A/B (section 5.3): production `main.rs` copied verbatim into the bench crate |

All `*-aead` configurations give the same security guarantees: AES-256-GCM per frame, sequence
number and end-of-stream flag in the associated data, and the output is renamed into place only
after the authenticated end-of-stream frame. **`*-plain` configurations give no confidentiality or
integrity.** They exist only to isolate data movement cost and are never compared for speedup
against `*-aead` as if they were equivalent.

**Equivalence classes used for speedup ratios** (a ratio is only computed within one class):

- **A**: 2 processes, AES-256-GCM, disk→disk: `prod-shm-aead`, `exp-shm-aead`, `exp-uds-aead`,
  `exp-uds-aead-defaultbuf`, `exp-file-aead`, `exp-mmap-aead`.
- **A′**: same as A, software AES: `prod-shm-aead-softaes` (ratio taken only against `prod-shm-aead`).
- **B**: 2 processes, plain, disk→disk: `exp-*-plain`.
- **C**: in-memory source, null sink: `mem-shm-*` vs `mem-uds-*`, with the caveat in 1.4.
- `copy-*` (single process) is a **floor/reference**, not an IPC competitor.

### 1.3 Timing boundaries

All timestamps come from `CLOCK_MONOTONIC_RAW`, which is system-wide, so timestamps taken in
different processes can be subtracted.

| Metric | Starts | Ends | Includes | Excludes |
|---|---|---|---|---|
| **e2e** (primary) | driver, just before spawning the first process | driver, after **both** processes are reaped by `wait4(2)` | spawn, exec, dyld, argument/key parsing, channel setup, source read, encryption, IPC, decryption, destination write + `fsync` + `rename`, teardown | SHA-256 verification, payload generation for disk configs, compilation |
| **transfer** | sender, immediately before the first byte | receiver, after `fsync` + `rename` | data path only | process start/exit, setup |
| **sender** | sender, first byte | sender done (shm: ring drained) | same boundary as the production writer's log line | — |
| **startup** | e2e start | sender first byte | spawn/exec/setup (and generating the payload for `mem-*`) | — |
| **shutdown** | receiver done | receiver reaped | exit, unmap, teardown | — |
| `prod_writer_internal` / `prod_reader_internal` | parsed from the production log lines (`Instant`-based) | | as logged by production | |

The production binaries do not print cross-process timestamps, so for `prod-*` the table shows the
production reader's internal timer in the "transfer" column (marked `*` in `results/summary.md`).

**Throughput** = payload (plaintext) bytes / time, with MiB = 2²⁰ B and GiB = 2³⁰ B. Frame overhead
(29 B per 256 KiB, 0.011%) and length prefixes are **not** counted as transferred bytes.

**CPU** = `ru_utime + ru_stime` of each child from `wait4(2)`, summed. **CPU util** = CPU / e2e.
**Peak RSS** = `ru_maxrss` (bytes on macOS). Shared-memory pages count toward the RSS of both
processes.

### 1.4 Caveats on the in-memory (`mem-*`) configurations

- Their **e2e includes generating the 1 GiB payload** in the sender (~280 ms startup), so e2e is not
  comparable to the disk configurations. Use **transfer** for these.
- `mem-shm-plain`: the null-sink receiver **never reads the payload bytes**. It only reads each
  record's length from shared memory. `mem-uds-plain`: the receiver must copy every byte out of the
  socket. The two plain transfer numbers therefore do not measure the same work, and no speedup
  ratio is computed between them. The `*-aead` variants *are* comparable, because decryption
  touches every byte on both transports.
- Null-sink runs are not hashed while timed. One extra **untimed** run per (config, size) with
  `--hash` (receiver-side SHA-256) verifies correctness (`kind=verify` in `runs.csv`).

---

## 2. Test conditions

| Item | Value (from `results/environment.txt`, `results/build_info.txt`) |
|---|---|
| Machine | **MacBook Air (Mac16,12), Apple M4** — 10 cores (4 performance + 6 efficiency), 16 GB, **fanless** |
| OS | macOS 26.5.2 (25F84), Darwin 25.5.0, xnu-12377.121.10, 16 KiB pages |
| Storage | internal SSD, APFS (Apple Fabric); 61 GiB free at start |
| Power | AC power, battery charging (61%), Low Power Mode off |
| Background load | load average 1.5–2.2 before the run (desktop session with an editor open); not controlled |
| Rust | rustc 1.99.0 (b940084d7 2026-09-28), LLVM 23.1.1, cargo 1.99.0, host aarch64-apple-darwin |
| Profile | release: opt-level 3, `lto = "fat"`, `codegen-units = 1`, panic = unwind; no `-C target-cpu` (default Apple baseline) |
| HW AES flags | `--cfg aes_armv8 --cfg polyval_armv8` (repo `.cargo/config.toml`) |
| Soft AES flags | `RUSTFLAGS="--cfg aes_force_soft --cfg polyval_force_soft"` (overrides the config flags; 0 AES instructions in the binary) |
| Crypto deps | aes-gcm 0.10.3, aes 0.8.4, polyval 0.6.2, ghash 0.5.1, ctr 0.9.2, cipher 0.4.4, cpufeatures 0.2.17, getrandom 0.2.15, libc 0.2.172 (identical in production and bench graphs) |
| Bench-only deps | sha2 0.10.9, memmap2 0.9.11 (+ clap/env_logger/log at the production versions for the A/B binaries) |
| Payload | deterministic pseudo-random bytes (SplitMix64 stream, seed `0x5275737442726964`), **incompressible**. SHA-256 recorded in `work/data/manifest.csv` |
| Sizes | 4 KiB, 64 KiB, 1 MiB, 16 MiB, 256 MiB, 1 GiB (plus 0 B, 1 B, 4095 B and 1,000,003 B for correctness) |
| Repetitions | **10 measured runs for every (config, size)**, after 1 warm-up run each (warm-ups recorded, `kind=warmup`) |
| Order | all 946 timed runs (86 warm-ups and 860 measured) in seeded random order (seed 20261011), then 12 verification runs |
| Cache state | **warm cache only**. Every source file is read once before the campaign and again by the warm-ups |
| Verification | SHA-256 of every destination file against the manifest after each run (outside the timing window); untimed hash runs for null-sink configs |

**Cold-cache results were not measured.** Evicting the page cache on macOS needs `sudo purge`, which
changes system-wide state, and the brief rules that out. No run in this report is labelled
cold-cache.

---

## 3. Results

Complete per-size tables (all six sizes, every config, p95, CV, CPU and RSS) are in
[`results/summary.md`](results/summary.md) and [`results/summary.csv`](results/summary.csv). Every
individual run is in [`results/runs.csv`](results/runs.csv).

### 3.1 Main comparison: 1 GiB, disk → disk, warm cache (n = 10 each, all verified)

| Config | Class | e2e median | e2e min–max | CV | Throughput (median e2e) | transfer median | CPU (median) | CPU util | Peak RSS send/recv |
|---|---|---|---|---|---|---|---|---|---|
| `prod-shm-aead` | A | **659.0 ms** | 650.9–887.6 | 10.9% | 1554 MiB/s (1.52 GiB/s) | 647.1 ms* | 1247 ms | 190% | 5.7 / 5.6 MiB |
| `exp-shm-aead` | A | 581.2 ms | 562.3–692.4 | 8.0% | 1762 MiB/s (1.72 GiB/s) | 579.1 ms | 1043 ms | 182% | 5.3 / 5.3 MiB |
| `exp-uds-aead` (4 MiB bufs) | A | 583.8 ms | 570.6–685.7 | 5.8% | 1754 MiB/s (1.71 GiB/s) | 580.6 ms | 1106 ms | 190% | 1.8 / 1.8 MiB |
| `exp-uds-aead-defaultbuf` (8 KiB) | A | 1017.9 ms | 985.7–1087.9 | 2.8% | 1006 MiB/s (0.98 GiB/s) | 1015.5 ms | 1537 ms | 151% | 1.8 / 1.8 MiB |
| `exp-file-aead` (staged) | A | 1439.5 ms | 1281.0–1603.2 | 8.2% | 711 MiB/s (0.69 GiB/s) | 1433.0 ms | 1189 ms | 83% | 1.8 / 1.8 MiB |
| `exp-mmap-aead` (staged) | A | 3297.4 ms | 2623.0–4062.5 | 15.8% | 311 MiB/s (0.30 GiB/s) | 3287.5 ms | 1532 ms | 47% | 1026 / 1026 MiB |
| `prod-shm-aead-softaes` | A′ | 5058.9 ms | 5006.6–5122.1 | 0.7% | 202 MiB/s (0.20 GiB/s) | 5044.5 ms* | 10028 ms | 198% | 5.6 / 5.7 MiB |
| `exp-shm-plain` | B | 566.3 ms | 539.7–1006.8 | 23.1% | 1808 MiB/s | 564.0 ms | 217 ms | 38% | 5.3 / 5.3 MiB |
| `exp-uds-plain` | B | 558.6 ms | 542.0–669.2 | 7.7% | 1833 MiB/s | 554.9 ms | 257 ms | 47% | 1.8 / 1.8 MiB |
| `exp-file-plain` | B | 1283.0 ms | 1118.5–1568.8 | 11.5% | 798 MiB/s | 1269.7 ms | 343 ms | 27% | 1.8 / 1.8 MiB |
| `exp-mmap-plain` | B | 1263.2 ms | 1201.5–3155.1 | 45.6% | 811 MiB/s | 1255.8 ms | 373 ms | 29% | 1026 / 1026 MiB |
| `copy-aead` (1 process) | ref | 1015.7 ms | 1004.6–1048.3 | 1.3% | 1008 MiB/s | 1014.2 ms | 1005 ms | 99% | 1.8 MiB |
| `copy-plain` (1 process) | ref | 560.5 ms | 544.6–601.8 | 3.1% | 1827 MiB/s | 558.3 ms | 152 ms | 27% | 1.8 MiB |

\* production reader's internal timer (attach → after `fsync`/`rename`), not a cross-process timestamp.

With n = 10, the nearest-rank p95 equals the maximum, so it is listed only in `summary.md` and is
not treated as a separate statistic.

**Speedup ratios** (medians, within one equivalence class only):

| Comparison (class) | Ratio |
|---|---|
| production hardware AES vs production software AES (A/A′) | 5058.9 / 659.0 = **7.68×** |
| `exp-shm-aead` vs `exp-uds-aead`, 4 MiB buffers (A) | 583.8 / 581.2 = **1.00×**. The ranges overlap, so no measurable difference |
| `exp-shm-aead` vs `exp-uds-aead-defaultbuf` (A) | 1017.9 / 581.2 = **1.75×** |
| `exp-shm-aead` vs `exp-file-aead` (A) | 1439.5 / 581.2 = **2.48×** |
| `exp-shm-aead` vs `exp-mmap-aead` (A) | 3297.4 / 581.2 = **5.67×** |
| `prod-shm-aead` vs `exp-uds-aead` (A) | 0.89× (production is slower; see 5.3) |
| `exp-shm-plain` vs `exp-uds-plain` (B) | 0.99× (no measurable difference) |

### 3.2 IPC + crypto without file I/O (in-memory source, null sink, transfer phase, n = 10)

| Config | 16 MiB | 256 MiB | 1 GiB | 1 GiB throughput | CPU (1 GiB) |
|---|---|---|---|---|---|
| `mem-shm-aead` | 14.9 ms | 118.5 ms | 469.4 ms | **2181 MiB/s** | 1218 ms |
| `mem-uds-aead` | 7.8 ms | 122.0 ms | 515.5 ms | **1986 MiB/s** | 1280 ms |
| `mem-shm-plain` | 7.5 ms | 13.0 ms | 33.1 ms | 30917 MiB/s† | 342 ms |
| `mem-uds-plain` | 1.0 ms | 13.7 ms | 67.2 ms | 15234 MiB/s† | 400 ms |

† Not comparable to each other (see 1.4): the shm null-sink receiver does not read the payload. These
numbers show a memcpy-speed ceiling, not realistic IPC throughput.

**Measured:** with encryption, the shared-memory ring moves 1 GiB in 469 ms versus 516 ms for a
tuned Unix domain socket, which is **1.10× faster** (ranges in `summary.csv`). That ~2.1–2.2 GiB/s
is close to single-core AES-GCM throughput (3.3).

At 16 MiB the order flips: UDS is faster. The 16 MiB shm figure is a median that includes the
reader's 10 ms attach-poll quantum, discussed in 3.5.

### 3.3 AES-256-GCM alone (in-process, in-memory, production `Sealer`/`Opener`, n = 10)

| Build | Chunk | Payload | Seal median | Seal throughput | Open median | Open throughput |
|---|---|---|---|---|---|---|
| hw | 256 KiB | 1 GiB | 426.7 ms | 2400 MiB/s | 425.4 ms | 2407 MiB/s |
| hw | 4 KiB | 1 GiB | 429.5 ms | 2384 MiB/s | 429.9 ms | 2382 MiB/s |
| hw | 1 MiB | 1 GiB | 426.3 ms | 2402 MiB/s | 425.3 ms | 2408 MiB/s |
| hw | 256 KiB | 4 KiB | 0.002 ms | 1875 MiB/s | 0.002 ms | 1786 MiB/s |
| soft | 256 KiB | 1 GiB (n = 5) | 4848.6 ms | 211 MiB/s | 4954.6 ms | 207 MiB/s |

Every size and chunk combination is in `results/aead_summary.csv`, and every repetition was verified
by SHA-256. Findings:

- Hardware AES-GCM runs at **~2.4 GiB/s per direction on one core**, almost independent of chunk size
  from 4 KiB to 1 MiB.
- The software fallback is **11.4× slower** (211 vs 2400 MiB/s).

### 3.4 Encryption cost inside the pipeline (1 GiB)

| Pair (same transport) | e2e Δ (aead − plain) | CPU Δ |
|---|---|---|
| exp-shm | +14.9 ms (581.2 vs 566.3) | +826 ms (1043 vs 217) |
| exp-uds | +25.3 ms (583.8 vs 558.6) | +849 ms (1106 vs 257) |
| copy (1 process) | +455.2 ms (1015.7 vs 560.5) | +853 ms (1005 vs 152) |

**Measured:** AES-GCM costs ~830–850 ms of CPU per GiB. That matches seal + open from the
microbenchmark (427 + 425 = 852 ms). In the two-process pipelines this cost is spread over two cores,
running in parallel with I/O, and adds only 15–25 ms of wall time. In a single process it is serial
and adds 455 ms.

These overlapping stage times must not be summed: 427 + 425 + 560 ≠ 581.

### 3.5 Small payloads, startup and shutdown

| Config | 4 KiB e2e median (min–max) | 64 KiB | 1 MiB |
|---|---|---|---|
| `spawn-baseline` (2 × noop) | 1.64 ms (1.50–1.90), payload 0 | | |
| `copy-plain` | 5.58 (4.64–6.56) | 5.83 | 6.23 |
| `exp-uds-aead` | 7.65 (3.36–10.96) | 7.05 | 8.01 |
| `exp-file-aead` | 7.16 (5.63–8.20) | 6.62 | 8.12 |
| `exp-shm-aead` | **16.10 (5.73–19.46)** | 16.25 | 18.07 |
| `prod-shm-aead` | **17.18 (7.63–19.23)** | 17.36 | 17.33 |

- **Startup** (spawn → first byte, 1 GiB, median): shm 1.5–1.8 ms; UDS 2.9–3.0 ms (the sender retries
  `connect` every 1 ms); staged file 1.5–1.7 ms.
- **Shutdown** (receiver done → reaped): 0.25–0.5 ms for shm, UDS and copy. **8–11 ms** for the staged
  transports, mostly the receiver's `unlink` of the 1 GiB staging file (*hypothesis*: deallocation of
  the APFS extents).
- **Measured:** shared memory is the **slowest** transport for payloads up to 1 MiB, with a median
  about 10 ms above UDS or the staged file. Its minimum (5.7 ms) matches theirs. The distribution is
  bimodal.
  *Hypothesis, strongly supported by the code:* the reader usually starts before the writer has
  created the segment, gets `NotFound`, and `Consumer::connect` sleeps **10 ms** before retrying. Runs
  where the segment already existed at the first attempt land at ~5.7 ms.

### 3.6 Reproduction of the historical figures

The original figures came from the previous session's log lines. Their methodology was the
**internal timers** of the writer and reader processes (`Instant` from after channel creation until
drained / renamed), with the reader and writer launched together from a shell, warm cache, data from
`dd if=/dev/urandom`, and **1–2 runs**. No raw files were saved, so they are **historical claims**.
The log lines quoted in the session were:

| Historical claim | Historical raw log values | Newly measured, same boundary (`prod_writer_internal`, n = 10) | Newly measured, process-level e2e (n = 10) | Reproducible? |
|---|---|---|---|---|
| "0.68 s" hw AES, 1 GiB | writer 675.0 ms / reader 685.5 ms (run 2); the run 1 before it took 879.1 / 1062.5 ms | median **648.1 ms** (637.3–722.4) | median **659.0 ms** (650.9–887.6) | **Yes, warm cache.** The median beats 0.68 s. 2 of the 10 e2e runs were slower (738.8, 887.6 ms). |
| "5.1 s" soft AES, 1 GiB | writer 5123.5 ms / reader 5125.8 ms (1 run) | median **5049.6 ms** (4994.7–5110.7) | median **5058.9 ms** (5006.6–5122.1) | **Yes.** |
| "~7.5× faster" | 5123.5 / 675.0 = 7.59× | 5049.6 / 648.1 = 7.79× | 5058.9 / 659.0 = 7.68× | **Yes** |
| "~1.5 GB/s" | ~1517 MiB/s | 1580 MiB/s | 1554 MiB/s | **Yes** |

**Caveats on the original claim:**

- The README calls 0.68 s "end to end". It was a single in-process timer reading. Two independent
  processes' wall clock is 11 ms higher at the median.
- It was the better of two runs: the first was 879 ms.
- It holds only in a warm page cache. Cold-cache behaviour is unmeasured.

---

## 4. Correctness and failure tests

| Suite | What | Result | Log |
|---|---|---|---|
| Production unit tests | `cargo test --release` in the workspace (10 tests) | **10 passed** | `results/checks.log` |
| Production lint | `cargo clippy --all-targets --all-features -- -D warnings` | **exit 0** | `results/checks.log` |
| Bench protocol tests | `bench/tests/protocol.rs` (9 tests) | **9 passed** | `results/checks.log` |
| Bench lint | `cargo clippy --all-targets --all-features -- -D warnings` | **exit 0** (after the fixes listed below) | `results/checks.log` |
| Process-level failure tests | `scripts/failure_tests.sh` against the production binaries (31 checks) | **31 passed, 0 failed** | `results/failure_tests.log` |
| Benchmark verification | SHA-256 of every output (disk sinks) and receiver-side SHA-256 (null sinks) | **958 / 958 runs ok** (946 timed + 12 verification), A/B experiment 33 / 33 ok | `results/runs.csv`, `results/ab_codegen.csv` |

Coverage:

- **Payloads:** empty (0 B), 1 B, 4 KiB, 1,000,003 B (not a multiple of the chunk), all byte-exact.
- **Ring:** wraparound and backpressure with a 4 KiB ring and 1000 B chunks (production binaries), and
  odd message sizes against a deliberately slow consumer (protocol test).
- **Keys:** missing key (writer and reader), malformed key, wrong key.
- **Protocol attacks:**
  - every single-bit flip in a frame
  - duplicated, truncated, undersized and reordered frames
  - a stream missing its end-of-stream frame
  - a corrupted ring length written by a third process, which is rejected rather than trusted
- **Peer failure:**
  - wrong-key reader: the writer exits non-zero instead of hanging
  - reader SIGKILLed mid-stream: the writer exits non-zero
  - writer SIGKILLed mid-stream: the reader exits non-zero, with no destination file and no `.part`
- **Cleanup:**
  - the segment is unlinked after success, after a failed transfer and after a writer error exit
  - a SIGKILLed writer leaves a stale segment (expected); a reader started first ignores it and the
    next transfer succeeds
- **Destination preservation:** an existing destination is byte-identical after a failed (wrong-key)
  transfer.
- **Argument validation:**
  - a second concurrent reader is refused, and the first still completes
  - invalid and over-long channel names are rejected
  - a non-power-of-two ring is rejected
  - a chunk that doesn't fit in the ring is refused
  - the reader times out cleanly with no output

**Failures during development, all bugs in the harness rather than in production code, and all fixed:**

1. **UDS receiver:** `setsockopt(SO_RCVBUF)` on an accepted socket whose peer had already
   disconnected returned `EINVAL` (4 KiB payloads). Fixed by setting it on the listener.
2. **Failure script, missing-key tests:** `env -u … t …` cannot run a shell function, so the binary
   was never invoked.
3. **Failure script, writer-kill tests:** backgrounding the timeout wrapper put the subshell's PID in
   `$!`, so `kill -9` never reached the writer and the transfer completed.
4. **Clippy:** two lints in the bench crate (an inherent method named `next`, and a complex type).

---

## 5. Analysis

### 5.1 Is 0.68 s reproducible?

**Yes, in a warm page cache on this machine.** Ten independently launched process pairs gave a
median of 659 ms (writer-internal timer: 648 ms), consistent with the historical 675 ms run.

The spread is narrow apart from two slow runs (739, 888 ms), so the claim is best stated as
*"~0.65–0.66 s median, warm cache, n = 10"*. Two things remain unestablished:

- **Cold-cache behaviour.** The source read would then hit the SSD rather than memory.
- **Behaviour under heavier or sustained load.** This is a fanless laptop (see 6).

### 5.2 Where the time goes at 1 GiB (disk → disk)

**Measured facts:**

- `copy-plain` is one process that just reads and writes the file, with no IPC and no crypto. It
  takes **560 ms**, with only 152 ms of CPU (27% utilisation), so it is mostly waiting.
- `exp-shm-plain` (566 ms), `exp-uds-plain` (559 ms), `exp-shm-aead` (581 ms) and `exp-uds-aead`
  (584 ms) are all within **0–4% of that single-process floor**.
- Adding AES-GCM costs ~840 ms of CPU but only 15–25 ms of wall time in the two-process pipelines.

**Interpretation:** at this size, with a warm source cache, the end-to-end time is bounded by the
file I/O path, not by the IPC mechanism and not by encryption. Each byte is read from the page cache
and then written to the APFS volume, followed by `fsync`.

*Hypothesis:* the binding stage is the destination write plus `fsync` to the SSD (~1.8 GiB/s
effective). That would explain why the faster IPC (3.2) does not show up end to end. A natural next
experiment is to write the output to a RAM disk, or to measure `fsync` separately (section 8).

Because of this floor, **shared memory and a tuned UDS are indistinguishable end to end** (581 vs
584 ms). The ring's advantage appears only once file I/O is removed: 1.10× at 1 GiB with
encryption (3.2).

### 5.3 Why the production binaries are ~13% slower than the experimental copy

**Measured:**

- `prod-shm-aead` 659 ms vs `exp-shm-aead` 581 ms (main campaign), and 655 vs 564 ms in the separate
  A/B (`results/ab_codegen.csv`, n = 10 each, interleaved).
- Per-process **user** CPU: 549 / 548 ms (production writer / reader) vs 448 / 437 ms (rbx). That is
  ~25% more.
- **System** CPU is the same: 65 / 87 ms vs 67 / 92 ms. The kernel side (I/O and shared memory) is
  therefore not the difference.
- Building the **unmodified production `main.rs` files inside the bench crate**, with identical
  dependency versions (verified by diffing the `cargo tree` graphs), identical flags and profile,
  gives **650 ms** and 545 / 542 ms of user CPU. The slowdown follows the production source, not the
  workspace, lock file or build flags.

*Hypothesis (not proven):* the per-byte work is the same AES-GCM calls, and the microbenchmark binary
does it at the measured 2.4 GiB/s. So the difference most likely comes from code generation at the
production call sites (different inlining or vectorisation decisions for the `aes-gcm` path inside
`writer::main` / `reader::main`), not from extra source-level work.

Confirming it needs a profiler with low attach latency or an assembly diff of the hot loop:
- `sample(1)` attached too late (~0.3 s) to profile a 0.65 s run.
- Instruments / `xctrace` was not tried.

### 5.4 Other bottlenecks found

1. **Reader attach polling (10 ms).** This dominates shared-memory latency for payloads up to 1 MiB
   (3.5). Production pays it on most short transfers.
2. **macOS default UDS buffers (8 KiB).** A UDS without tuning is 1.75× slower than with 4 MiB
   buffers at 1 GiB. This matters to anyone comparing against "plain sockets".
3. **Staged transports are sequential.** The staged file (1.44 s) and staged mmap (3.30 s) cannot
   overlap sender and receiver, and need payload-sized temporary space. Staged mmap also has
   1 GiB of peak RSS per process and the highest variance.
   *Hypothesis:* copy-on-write faults from decrypting in place in a `MAP_PRIVATE` mapping (65,536
   × 16 KiB pages), plus writeback of the sender's dirty `MAP_SHARED` pages.
4. **First launch of a freshly built binary.** In the pre-campaign smoke test
   (`results/smoke_first_launch.csv`), the first execution of each newly built binary took 0.7–1.4 s,
   against 6–30 ms afterwards.
   *Hypothesis:* the macOS first-launch security assessment of new executables (not verified).
   Warm-up runs remove it from the measured data. Users running a fresh build will see it once.

### 5.5 Outliers and drift

Every run is kept. The 1 GiB outliers above 1.15× the config median:

| Config | Value | Run order |
|---|---|---|
| `prod-shm-aead` | 738.8, 887.6 ms | #460, #658 |
| `exp-shm-plain` | 1006.8 ms | #173 |
| `exp-shm-aead` | 692.4, 682.2 ms | #748, #919 |
| `exp-uds-plain` | 669.2, 639.8 ms | |
| `exp-mmap-plain` | 2964.6, 2310.0, 3155.1 ms | #273, #307, #376 |

The runs immediately before them show no consistent pattern (they include staged, mem and small
runs). *Hypotheses, none verified:*

- deferred writeback or APFS work left over from earlier 1 GiB writes and deletions (staging files
  are written without `fsync`)
- background desktop activity (load average 1.5–2.2)

**Thermal:** `pmset -g therm` recorded no thermal or performance warning before or after the
campaign. The medians of the first and second half of each config's runs, in execution order, show
no systematic slowdown (e.g. `prod-shm-aead` 664.8 → 652.6 ms, `exp-shm-aead` 582.7 → 579.7 ms).
`exp-mmap-plain` is the exception, but only because its three outliers happened to fall in the first
half. Direct temperature or frequency data would need `sudo powermetrics` and was not collected.

---

## 6. Limitations and tests that could not run

| Not done | Why |
|---|---|
| **Cold-cache runs** | Needs `sudo purge` (system-wide, excluded by the brief). All results are warm-cache |
| CPU frequency / temperature traces | `powermetrics` needs root. Thermal state was inferred from `pmset -g therm` and run-order drift only |
| Profile of the production hot loop | `sample(1)` attaches ~0.3 s late, which is too slow for a 0.65 s transfer. Instruments / `xctrace` not tried |
| Control of background load | Desktop session with other apps. Load average 1.5–2.2 was recorded, not controlled |
| Linux comparison | Out of scope (the target is the M4 Mac) |
| Compressible payloads | Not run. AES output is incompressible either way and APFS does not compress transparently by default, so no effect is expected (untested) |
| Equivalent plain IPC-only comparison (`mem-*-plain`) | The shm null-sink receiver does not touch the payload while the UDS receiver must copy it out. These numbers are reported but not compared |
| p95 as a separate statistic | With n = 10, nearest-rank p95 equals the maximum. It is listed in `summary.md` but carries no extra information |
| hyperfine | Not installed. The custom driver was needed anyway for two-process timing, `wait4` rusage and cross-process timestamps |
| Large-chunk / large-ring production tuning sweep | Only 256 KiB / 4 MiB (production default) was measured end to end. A 1 MiB / 16 MiB point from the historical session is not re-measured |

---

## 7. Reproducing

From the repository root (`~4 GiB` free disk needed under `bench/work/`):

```bash
cd bench
./scripts/run_all.sh                 # everything: env, build, gen, tests, run, aead, summarize (~20 min)
```

Or stage by stage:

```bash
cd bench
./scripts/env.sh                     # -> results/environment.txt
./scripts/build.sh                   # all binaries + AES instruction counts -> results/build_info.txt
./target/release/driver gen          # payloads + SHA-256 manifest -> work/data/
./scripts/run_all.sh tests           # unit tests + clippy -> results/checks.log; failure suite -> results/failure_tests.log
./target/release/driver run --reps 10 --warmup 1 --seed 20261011 --out results/runs.csv
./target/release/driver aead --out results/aead.csv
./target/release/driver summarize --runs results/runs.csv --aead results/aead.csv

# Supplementary codegen A/B (section 5.3)
./target/release/driver run --configs prod-shm-aead,prodsrc-shm-aead,exp-shm-aead \
    --sizes 1073741824 --reps 10 --warmup 1 --seed 777 --first-id 10000 --out results/ab_codegen.csv

# A single configuration or size, e.g. only the production path at 1 GiB:
./target/release/driver run --configs prod-shm-aead --sizes 1073741824 --reps 10 --out work/one.csv
```

Individual transports can also be run by hand:

```bash
export RUSTBRIDGE_KEY=$(openssl rand -hex 32)
./target/release/rbx uds-recv --crypto 1 --socket /tmp/rb.sock --sockbuf 4194304 --output /tmp/out.bin &
./target/release/rbx uds-send --crypto 1 --socket /tmp/rb.sock --sockbuf 4194304 --input work/data/payload_1073741824.bin
./target/release/rbx aead --chunk 262144 --size 1073741824 --reps 10
```

---

## 8. Recommended next experiments

Ordered by expected value, based on the measured bottlenecks:

1. **Find the production code-generation gap (5.3).** Diff the disassembly of the seal/open loop in
   `writer` vs `rbx`, or profile with Instruments' Time Profiler. Then try `#[inline(never)]`
   wrappers around `seal_in_place` / `open_in_place` in `shared_ipc`. Potential gain: ~13% end to end.
2. **Remove the 10 ms attach poll.** For example, poll faster at first (1 ms, then back off), or have
   the reader create the segment and the writer attach. Measure 4 KiB–1 MiB transfers again: if the
   hypothesis is right, the median should drop from ~16 ms to ~6 ms.
3. **Isolate the destination write.** Repeat the 1 GiB disk runs with the output on a RAM disk
   (`hdiutil attach -nomount ram://…` needs no root) and with `fsync` timed separately. This tests the
   "write + fsync is the floor" hypothesis (5.2).
4. **Cold-cache runs**, if `sudo purge` becomes acceptable, or using a fresh 1 GiB file per run read
   with `F_NOCACHE`, so source reads hit the SSD.
5. **Event-driven wakeups instead of sleep polling** (`os_sync_wait_on_address` on macOS 14.4+).
   Measure latency at small sizes and CPU use while idle.
6. **Chunk and ring sweep** (64 KiB–4 MiB chunks × 1–64 MiB rings) for `prod-shm-aead`, including
   the historical 1 MiB / 16 MiB point.
7. **Parallel AES-GCM** (two worker threads per side) for the in-memory case, where a single AES
   core at ~2.4 GiB/s is the limit (3.2/3.3). This only matters if file I/O stops being the bound.
8. **Re-run on a machine with a fan, or under sustained load**, to quantify thermal sensitivity.

---

## 9. Artifacts

| Path | Contents |
|---|---|
| `bench/BENCHMARK_REPORT.md` | this report |
| `bench/results/runs.csv` | every run of the main campaign (958 rows: 86 warm-up, 860 measured, 12 verify) |
| `bench/results/summary.csv`, `bench/results/summary.md` | per-(config, size) statistics and tables |
| `bench/results/aead.csv`, `bench/results/aead_summary.csv` | AES-GCM microbenchmark, every repetition and summary |
| `bench/results/ab_codegen.csv` | supplementary production-vs-bench-build A/B (33 runs) |
| `bench/results/smoke_first_launch.csv` | pre-campaign smoke run showing the first-launch effect |
| `bench/results/environment.txt`, `bench/results/build_info.txt` | environment, versions, flags, AES instruction counts, binary hashes |
| `bench/results/checks.log`, `bench/results/failure_tests.log` | unit tests, clippy and failure-suite output |
| `bench/results/thermal_before.txt`, `bench/results/thermal_after.txt` | `pmset -g therm` around the campaign |
| `bench/results/run_progress.log` | driver progress log of the main campaign |
| `bench/src/bin/driver.rs` | orchestration, timing, rusage, verification, statistics |
| `bench/src/bin/rbx.rs` | experimental transports, copy baseline, AEAD microbenchmark |
| `bench/src/bin/prodsrc_writer.rs`, `prodsrc_reader.rs` | verbatim copies of the production `main.rs` (A/B only) |
| `bench/src/lib.rs`, `bench/tests/protocol.rs` | shared helpers; protocol correctness tests |
| `bench/scripts/{run_all,build,env,failure_tests}.sh` | reproduction scripts |
