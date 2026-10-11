#!/bin/bash
# Records the benchmark environment to results/environment.txt (read-only commands only).
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
{
  echo "# Environment ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
  system_profiler SPHardwareDataType 2>/dev/null | grep -E 'Model Name|Model Identifier|Chip|Total Number of Cores|Memory' | sed 's/^ *//'
  echo "hw.model: $(sysctl -n hw.model)"
  echo "cpu: $(sysctl -n machdep.cpu.brand_string)  arch: $(uname -m)"
  echo "cores: $(sysctl -n hw.ncpu) total, perf=$(sysctl -n hw.perflevel0.physicalcpu) eff=$(sysctl -n hw.perflevel1.physicalcpu)"
  echo "memsize: $(sysctl -n hw.memsize) bytes; pagesize: $(sysctl -n hw.pagesize)"
  echo "cache line: $(sysctl -n hw.cachelinesize); l2(perf): $(sysctl -n hw.perflevel0.l2cachesize)"
  echo "arm features: AES=$(sysctl -n hw.optional.arm.FEAT_AES) PMULL=$(sysctl -n hw.optional.arm.FEAT_PMULL) SHA256=$(sysctl -n hw.optional.arm.FEAT_SHA256)"
  sw_vers | sed 's/^/macOS /'
  echo "kernel: $(uname -v)"
  echo "UDS default buffers: sendspace=$(sysctl -n net.local.stream.sendspace) recvspace=$(sysctl -n net.local.stream.recvspace) maxsockbuf=$(sysctl -n kern.ipc.maxsockbuf)"
  echo "power: $(pmset -g batt | head -2 | tr '\n' ' ')"
  echo "thermal: $(pmset -g therm 2>/dev/null | tr '\n' ' ')"
  echo "low power mode: $(pmset -g | grep -i lowpowermode | xargs)"
  echo "filesystem: $(diskutil info / | grep -E 'File System Personality|Solid State|Protocol' | sed 's/^ *//' | tr '\n' ';')"
  echo "free disk: $(df -h . | tail -1)"
  echo "load: $(uptime)"
  rustc -vV
  cargo -V
  echo "deps (bench + shared_ipc):"; cargo tree -e normal --prefix none | sort -u | grep -E '^(aes|aes-gcm|polyval|ghash|ctr|cipher|cpufeatures|getrandom|libc|sha2|memmap2|anyhow) '
  echo "production repo state: $(cd .. && git rev-parse --short HEAD) + uncommitted changes:"; (cd .. && git status --short)
} > results/environment.txt 2>&1
cat results/environment.txt
