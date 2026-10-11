#!/bin/bash
# Builds every binary the benchmark uses and records what instructions they contain.
#   - production writer/reader, hardware AES   -> ../target/release            (repo default flags)
#   - production writer/reader, software AES   -> work/target-soft/release     (same source, forced soft)
#   - benchmark rbx/driver, hardware AES       -> target/release
#   - benchmark rbx, software AES              -> work/target-soft-bench/release
# RUSTFLAGS overrides the repo's .cargo/config.toml rustflags entirely, and the *_force_soft
# cfgs force the RustCrypto software backends even if armv8 cfgs were somehow present.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
SOFT="--cfg aes_force_soft --cfg polyval_force_soft"
OUT=results/build_info.txt

( cd .. && cargo build --release -p writer -p reader )
RUSTFLAGS="$SOFT" cargo build --release --manifest-path ../Cargo.toml -p writer -p reader --target-dir work/target-soft
cargo build --release
RUSTFLAGS="$SOFT" cargo build --release --bin rbx --target-dir work/target-soft-bench

count() { otool -tv "$1" | grep -cE "^\S+\s+$2\b" || true; }
{
  echo "# Build info ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  echo "profile: release (opt-level=3, lto=fat, codegen-units=1, debug=false, panic=unwind)"
  echo "hw rustflags (from ../.cargo/config.toml): --cfg aes_armv8 --cfg polyval_armv8"
  echo "soft RUSTFLAGS: $SOFT"
  echo "target-cpu: default for aarch64-apple-darwin (apple-m1 baseline); no -C target-cpu=native"
  echo
  printf "%-50s %6s %6s %6s %6s\n" binary aese aesmc pmull pmull2
  for b in ../target/release/writer ../target/release/reader work/target-soft/release/writer work/target-soft/release/reader target/release/rbx work/target-soft-bench/release/rbx; do
    printf "%-50s %6s %6s %6s %6s\n" "$b" "$(count $b aese)" "$(count $b aesmc)" "$(count $b pmull)" "$(count $b pmull2)"
  done
  echo
  echo "sha256 of binaries:"; shasum -a 256 ../target/release/writer ../target/release/reader work/target-soft/release/writer work/target-soft/release/reader target/release/rbx target/release/driver work/target-soft-bench/release/rbx
} | tee "$OUT"
