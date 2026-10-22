# Single-message latency benchmark

This complements [`BENCHMARK_REPORT.md`](BENCHMARK_REPORT.md), which measures **whole-file
throughput** across process launches. This document measures **single-message round-trip
latency** in steady state, including a raw (no-encryption) shared-memory flow.

## Flows

Each flow runs as two independently launched processes (a requester and a responder) that
exchange a fixed payload. All flows reuse the production `shared_ipc` crate.

| Flow | Transport | Encryption | Notes |
|---|---|---|---|
| `shm-raw` | `shared_ipc` ring (two rings, one per direction) | **none** | **Shared Memory — Raw Data (No Encryption).** Payload written into and read directly from the ring; no encrypt/decrypt, no serialization. |
| `shm-aead` | same ring | AES-256-GCM per message | Same path, plus production framing (seal on send, open on receive). |
| `uds-raw` | one bidirectional `AF_UNIX` stream socket | none | Length-prefixed raw payload. |
| `uds-aead` | same socket | AES-256-GCM per message | Length-prefixed production frame. |

The raw flow measures **IPC and synchronization overhead without cryptographic overhead**. It
is *not* an apples-to-apples comparison with the encrypted flows: the raw flow provides no
confidentiality or integrity. It exists to separate transport cost from crypto cost.

### Raw shared-memory protocol

The SPSC ring carries data in one direction, so the round trip uses two rings: `req`
(requester → responder) and `resp` (responder → requester). Each side **creates** one ring
and **connects** to the other, so start order does not matter. The producer owns its ring and
unlinks it on exit; a crashed peer is detected by the existing PID-liveness check. The reader
only ever observes a fully published message, because publication is a release-store of the
ring head that the reader acquires before reading (the same discipline the encrypted flow
uses — the raw flow simply skips the seal/open step). Integrity is verified every round by
comparing the echo against the sent payload; a flow that corrupted or dropped data would fail
`verified`.

## Methodology

- **Metric:** round-trip time (RTT) — one request sent and echoed back — timed in the
  requester with `clock_gettime(CLOCK_MONOTONIC_RAW)`.
- **Warm-up vs measured:** the first `--warmup` round trips are discarded; the next
  `--rounds` are recorded. Defaults: 5,000 warm-up, 50,000 measured.
- **Distribution:** min, p50, p95, p99, max, mean (nearest-rank percentiles over all measured
  samples).
- **Correctness:** every echo is compared to the sent payload; the run reports `verified`.
- **Configurable:** `--sizes`, `--rounds`, `--warmup`, `--configs`, `--out`.
- **Output:** a table ([`results/latency.md`](results/latency.md)) and machine-readable
  [`results/latency.json`](results/latency.json).

Latency and throughput are deliberately separate measurements: throughput streams a large
file and is bound by I/O and bulk crypto; latency sends one small message at a time and is
bound by the wakeup/scheduling path.

## Results

Environment: **Apple M4 MacBook Air (fanless), macOS 26.5.2, rustc 1.99.0**, release build
(`lto=fat`, `codegen-units=1`), ARMv8 AES enabled, warm process state, 50,000 measured round
trips per cell. Full environment in [`results/environment.txt`](results/environment.txt).

| flow | bytes | p50 µs | p95 µs | p99 µs | min µs | mean µs | verified |
|---|---|---|---|---|---|---|---|
| shm-raw | 64 | 0.33 | 0.75 | 0.92 | 0.12 | 0.42 | yes |
| shm-raw | 1024 | 0.54 | 0.92 | 1.00 | 0.12 | 0.59 | yes |
| shm-raw | 65536 | 2.62 | 4.33 | 6.33 | 1.50 | 2.91 | yes |
| shm-aead | 64 | 0.33 | 0.46 | 0.79 | 0.17 | 0.36 | yes |
| shm-aead | 1024 | 2.33 | 2.62 | 3.25 | 1.75 | 2.25 | yes |
| shm-aead | 65536 | 106.92 | 133.83 | 145.71 | 99.29 | 111.90 | yes |
| uds-raw | 64 | 4.33 | 7.58 | 9.12 | 2.92 | 4.96 | yes |
| uds-raw | 1024 | 4.33 | 7.58 | 8.83 | 3.00 | 4.80 | yes |
| uds-raw | 65536 | 71.08 | 81.33 | 93.17 | 43.25 | 71.74 | yes |
| uds-aead | 64 | 4.33 | 7.12 | 8.58 | 3.04 | 4.65 | yes |
| uds-aead | 1024 | 8.42 | 10.42 | 15.92 | 4.54 | 8.64 | yes |
| uds-aead | 65536 | 177.29 | 191.96 | 210.42 | 144.83 | 178.01 | yes |

(One representative run; exact tail values vary a little between runs because the machine is
not isolated. `min` is the cleanest signal of the mechanism's floor.)

## Interpretation

- **Small-message latency: raw shared memory is ~13× lower than a Unix domain socket.** At 64 B,
  shm-raw p50 is 0.33 µs versus 4.33 µs for uds-raw. The gap is the kernel round trip: a UDS
  message costs two `write(2)`/`read(2)` pairs plus scheduling, while the ring exchanges data
  through mapped memory with no syscall on the hot path.
- **That latency comes from busy-spinning, not from the condvar.** The ring's waiter spins and
  yields before it ever blocks (see `Backoff` in `shared_ipc`). At these message rates both
  processes stay in the spin phase, so a message is seen almost immediately — at the cost of
  burning CPU while waiting. UDS blocks in the kernel instead: higher latency, near-zero idle
  CPU. This is the central trade-off, not a free win.
- **Encryption is cheap for small messages, significant for large ones.** At 64 B, shm-aead ≈
  shm-raw (AES of 64 B is negligible). At 64 KiB, shm-aead p50 is 107 µs versus 2.6 µs raw:
  four AES-256-GCM operations per round trip (encrypt+decrypt each way) dominate — consistent
  with the ~2.4 GiB/s per-core AES-GCM measured in the throughput report.
- **UDS large-payload latency is bound by copying** (70 µs raw at 64 KiB), and adding AES
  stacks on top (177 µs).

## macOS limitation found while building this benchmark

This benchmark exposed a real defect in the event-driven wakeup added earlier. On macOS a
**process-shared pthread condvar is bound to the waiting mutex's virtual address**, which
differs between two separately-`exec`'d processes mapping the same segment, so a cross-process
`pthread_cond_timedwait` is rejected with `EINVAL`. It stayed hidden because throughput runs
stream fast enough that the consumer almost never *parks* (it finds data during the spin
phase), and the unit tests park within a single process (same address). The echo benchmark is
the first workload that reliably parks a consumer in one process while the producer is busy in
another — e.g. `shm-aead` at 64 KiB, where the responder spends ~100 µs on AES.

`shared_ipc` now treats an unexpected `cond_timedwait` error as a signal to **degrade to timed
polling** (`FALLBACK_SLEEP`) instead of failing. Correctness and the no-hang guarantees are
preserved on both platforms; on macOS the idle/parked path falls back to polling rather than a
true event wakeup (Linux still gets the event wakeup). This is why `shm-aead` at 64 KiB shows a
higher floor than the pure AES cost alone would predict. A full fix (an `os_sync_wait_on_address`
/ `futex` wakeword, as noted in the roadmap) is left as future work.

## Reproduce

```bash
cd bench
cargo build --release
# all flows, default sizes (64 B, 1 KiB, 64 KiB), 50k measured round trips each:
./target/release/driver latency
# custom:
./target/release/driver latency --sizes 64,4096 --rounds 100000 --warmup 10000 \
    --configs shm-raw,uds-raw --out results/latency.json
```

Outputs: `results/latency.md` (table) and `results/latency.json` (machine-readable).
Correctness tests for the raw flow: `cargo test --release --test raw_roundtrip`.
