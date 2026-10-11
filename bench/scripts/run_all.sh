#!/bin/bash
# Full reproduction of the benchmark campaign. Takes ~15-20 minutes on an Apple M4.
# Needs ~4 GiB free disk under bench/work (payloads 1.3 GiB + one output + one staging file).
# Stages can be selected: scripts/run_all.sh [env] [build] [gen] [tests] [run] [aead] [summarize]
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
stages=${*:-env build gen tests run aead summarize}
has() { [[ " $stages " == *" $1 "* ]]; }
D=./target/release/driver

has env   && ./scripts/env.sh >/dev/null
has build && ./scripts/build.sh
has gen   && $D gen
if has tests; then
  { echo "### production: cargo test --release"; (cd .. && cargo test --release 2>&1 | grep -E 'test result|FAILED|panicked');
    echo "### production: clippy --all-targets --all-features -D warnings"; (cd .. && cargo clippy --all-targets --all-features -- -D warnings >/dev/null 2>&1; echo "exit=$?");
    echo "### bench: cargo test --release"; cargo test --release 2>&1 | grep -E 'test result|FAILED|panicked';
    echo "### bench: clippy --all-targets --all-features -D warnings"; cargo clippy --all-targets --all-features -- -D warnings >/dev/null 2>&1; echo "exit=$?"; } > results/checks.log 2>&1
  ./scripts/failure_tests.sh > results/failure_tests.log 2>&1 || echo "failure tests reported FAILs, see results/failure_tests.log"
fi
if has run; then
  pmset -g therm > results/thermal_before.txt 2>&1 || true
  $D run --reps 10 --warmup 1 --seed 20261011 --out results/runs.csv 2> results/run_progress.log
  pmset -g therm > results/thermal_after.txt 2>&1 || true
fi
has aead      && $D aead --out results/aead.csv 2> results/aead_progress.log
has summarize && $D summarize --runs results/runs.csv --aead results/aead.csv
