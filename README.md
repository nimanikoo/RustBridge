# RustBridge

**Zero-copy, encrypted inter-process messaging over kernel shared memory, written in Rust.**

RustBridge moves data between two processes on the same machine through a lock-free
ring buffer that lives in POSIX shared memory (`shm_open` + `mmap`). Every message is
encrypted and authenticated with AES-256-GCM **in place, inside the shared mapping**, so
the payload is never copied into an intermediate buffer, and no socket, pipe or file
sits in the data path.

It runs natively on **macOS** (Intel and Apple Silicon) and **Linux**.

```
┌──────────────┐   read(2)    ┌───────────────────────── shared memory ─────────────────────────┐   write(2)   ┌──────────────┐
│ input file   │ ───────────▶ │ writer: seal in place ─▶ [ ring buffer ] ─▶ open in place: reader │ ───────────▶ │ output file  │
└──────────────┘              └──────────────────────────────────────────────────────────────────┘              └──────────────┘
```

## Highlights

- **Kernel IPC, not files.** Both processes map the same physical pages via `shm_open(2)` / `mmap(2)`. No `/dev/shm` dependency (which does not exist on macOS), and no `fsync`.
- **Lock-free SPSC ring.** One producer, one consumer, synchronised only by two atomic counters with acquire/release ordering. The counters sit on separate cache lines, and each side caches the other's index to avoid cache-line ping-pong.
- **Zero-copy.** The writer `read(2)`s the file straight into a reserved ring slot and encrypts it there. The reader decrypts in the ring and `write(2)`s from it.
- **Authenticated streaming encryption.** AES-256-GCM per message. The sequence number and end-of-stream flag are bound into the AEAD associated data, so tampering, reordering, replay, dropped frames and truncation are all detected.
- **Hardware crypto.** Uses ARMv8 AES/PMULL on Apple Silicon (enabled in [`.cargo/config.toml`](.cargo/config.toml)) and AES-NI/CLMUL on x86_64.
- **Robust lifecycle.** Either side can start first. The other side waits for it. A crashed peer is detected through a PID liveness check, and stale segments from killed runs are replaced automatically. Output is written to a `.part` file and renamed only after the whole stream has been verified.
- **Pure Rust, no system libraries.** No OpenSSL install or `OPENSSL_DIR` needed.

## Quick start

### Prerequisites

- Rust **1.88+**. Install with [rustup](https://rustup.rs):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- macOS 11+ or Linux. No other dependencies.

### Build

```bash
git clone https://github.com/nimanikoo/RustBridge.git
cd RustBridge
cargo build --release
```

### Run

Both processes need the same 256-bit key, given as 64 hex characters:

```bash
export RUSTBRIDGE_KEY=$(openssl rand -hex 32)
```

Start the reader and writer in two terminals (with the same `RUSTBRIDGE_KEY` exported in each), in either order:

```bash
# terminal 1
./target/release/reader                  # writes test_data/output.jpg

# terminal 2
./target/release/writer                  # sends test_data/input.jpg
```

Or in one shell:

```bash
./target/release/reader & ./target/release/writer; wait
cmp test_data/input.jpg test_data/output.jpg && echo "identical"
```

Example output:

```
[INFO  reader] waiting for writer on channel /rustbridge...
[INFO  writer] channel /rustbridge ready (4194304 byte ring), sending test_data/input.jpg
[INFO  reader] attached to /rustbridge
[INFO  writer] sent 86157 bytes in 3.207 ms
[INFO  reader] received 86157 bytes in 8.095 ms -> test_data/output.jpg
```

## Usage

```text
writer [INPUT] [--channel NAME] [--ring-size BYTES] [--chunk-size BYTES]
reader [OUTPUT] [--channel NAME] [--timeout SECONDS]
```

| Option | Binary | Default | Description |
| --- | --- | --- | --- |
| `INPUT` | writer | `test_data/input.jpg` | File to send |
| `OUTPUT` | reader | `test_data/output.jpg` | Destination for the decrypted file |
| `--channel` | both | `/rustbridge` | Shared memory name. Must start with `/`, at most 31 bytes (macOS limit) |
| `--ring-size` | writer | `4194304` (4 MiB) | Ring capacity. Power of two, at least 4096 |
| `--chunk-size` | writer | `262144` (256 KiB) | Plaintext bytes per message. Must fit in the ring |
| `--timeout` | reader | `30` | Seconds to wait for the writer to appear |

| Environment variable | Description |
| --- | --- |
| `RUSTBRIDGE_KEY` | **Required.** 32-byte AES key as 64 hex characters |
| `RUST_LOG` | Log level (`error`, `warn`, `info` (default), `debug`, `trace`) |

Run several independent transfers at once by giving each pair its own `--channel`.

## Performance

Transferring a 1 GiB file of random data end to end (disk read → encrypt → shared memory
→ decrypt → disk write and `fsync`) on an **Apple M4, macOS 26**, release build:

| Configuration | Time | Throughput |
| --- | --- | --- |
| Original (file in `/dev/shm`, OpenSSL CBC, whole file in memory) | does not run on macOS | n/a |
| Refactor, software AES fallback | 5.12 s | ~200 MiB/s |
| **Refactor, hardware AES (default)** | **0.68 s** | **~1.5 GiB/s** |

Memory use is bounded by the ring size (4 MiB by default) rather than the file size, because
the file is streamed in chunks instead of being loaded into memory whole.

Tuning tips:

- Bigger chunks (`--chunk-size 1048576`) mean fewer frames and less per-message overhead. Keep the ring at least 4× the chunk size so both sides can work in parallel.
- For benchmarking on your own machine only, `RUSTFLAGS="-C target-cpu=native"` can help a little more. Don't ship binaries built that way.

## How it works

### Crates

| Crate | Role |
| --- | --- |
| [`shared_ipc`](shared_ipc/src) | Library: shared memory, ring buffer, crypto |
| [`writer`](writer/src/main.rs) | Producer binary: reads a file, encrypts, publishes |
| [`reader`](reader/src/main.rs) | Consumer binary: receives, verifies, decrypts, writes |

`shared_ipc` has three modules:

- [`shm.rs`](shared_ipc/src/shm.rs): `ShmSegment`, a thin RAII wrapper around `shm_open`, `ftruncate`, `mmap`, `munmap` and `shm_unlink`.
- [`ring.rs`](shared_ipc/src/ring.rs): `Producer` / `Consumer`, the lock-free SPSC message ring.
- [`crypto.rs`](shared_ipc/src/crypto.rs): `Sealer` / `Opener`, in-place AES-256-GCM stream framing.

### Shared memory layout

```text
offset 0     ┌──────────────────────────────────────────────┐
             │ magic u64 · capacity u64                      │  cache line 0
             │ producer_pid u32 · consumer_pid u32           │
offset 64    ├──────────────────────────────────────────────┤
             │ head u64   (written only by the producer)     │  cache line 1
offset 128   ├──────────────────────────────────────────────┤
             │ tail u64   (written only by the consumer)     │  cache line 2
offset 192   ├──────────────────────────────────────────────┤
             │ data[capacity]   (power-of-two ring)          │
             └──────────────────────────────────────────────┘
```

`head` and `tail` are monotonically increasing byte counters. A slot's offset is
`pos & (capacity - 1)`. Each record is `[len u32][reserved u32][payload]`, padded to 8 bytes.
A record never wraps around the end of the buffer: if it would not fit, the producer writes
a `WRAP` marker and continues at offset 0.

### Protocol

1. **Writer** removes any stale segment, creates a new one, sizes it with `ftruncate`, maps it, and publishes `magic` last with a release store.
2. **Reader** polls `shm_open` until the segment exists, `magic` is set and the producer PID is alive. It then claims the single consumer slot with a compare-and-swap on `consumer_pid`.
3. **Writer**, for each chunk: `reserve()` a slot (waits for free space), `read(2)` file bytes into it, encrypt in place, then `commit()`, which writes `len` and does a release store of `head`.
4. **Reader**: an acquire load of `head`, validation of the record bounds (the shared memory is never trusted), decrypt and verify in place, then `write(2)` to the output. Dropping the `Message` does a release store of `tail`, freeing the space.
5. **Writer** sends an authenticated end-of-stream frame, waits until `tail == head`, and unlinks the segment on exit.

Waiting uses an adaptive backoff: spin briefly, then `sched_yield`, then sleep for 50 µs.
That gives low latency under load without burning a CPU core while idle. While sleeping,
each side periodically checks with `kill(pid, 0)` that its peer is still alive.

### Message frame

```text
[flags u8][nonce 12 B][ciphertext ...][GCM tag 16 B]
AAD = sequence_number (u64 LE) || flags
```

Nonces are a random per-stream 96-bit base XORed with the sequence number, so they never
repeat within a stream, and the chance of a repeat across streams is negligible. The reader
expects sequence numbers 0, 1, 2, … and verifies each tag before using any plaintext.

## Security model

- **Confidentiality and integrity** of every message, and of the stream as a whole (order and completeness), under a shared 256-bit key.
- The segment is created with mode `0600`, so only the same user can map it.
- Lengths and offsets read from shared memory are bounds-checked before use. A buggy or hostile peer can make the transfer fail, but it cannot cause out-of-bounds memory access.
- **Out of scope:** key exchange and key storage. Pass the key however your environment manages secrets. A process running as the same user can always read your memory anyway.

## Testing

```bash
cargo test                                   # unit + concurrency tests
cargo clippy --all-targets -- -D warnings    # lints
```

The tests cover:

- cross-thread streaming of 20,000 messages with wrap-around
- capacity and size validation
- single-consumer enforcement
- detection of a consumer that detaches early
- crypto round-trips
- rejection of tampered, flag-flipped, wrong-key and out-of-order frames

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `RUSTBRIDGE_KEY is not set` | `export RUSTBRIDGE_KEY=$(openssl rand -hex 32)` in **both** shells, with the same value |
| `authentication failed` | The reader and writer use different keys |
| `shared memory name must look like "/name"…` | Names must start with `/`, contain no other `/`, and be at most 31 bytes on macOS |
| `another consumer (pid N) is already attached` | Only one reader per channel. Use a different `--channel` |
| Reader times out with `No such file or directory` | The writer didn't start within `--timeout` seconds |
| Writer seems stuck on "waiting for reader" | It waits for a reader to attach and drain the stream. Start the reader, or press Ctrl-C |

Unlike Linux, macOS has no `/dev/shm` to inspect. Leftover segments from killed runs are
harmless: the next writer on the same channel replaces them.

## Roadmap

- Futex (Linux) / `os_sync_wait_on_address` (macOS 14.4+) wakeups instead of sleep polling
- Multi-producer / broadcast topologies
- Key derivation (HKDF) from a passphrase, or an X25519 handshake between peers
- Criterion benchmarks and a GitHub Actions CI matrix (macOS + Linux)

## Contributing

Issues and pull requests are welcome. Please run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`
and `cargo test` before submitting.
