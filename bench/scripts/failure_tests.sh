#!/bin/bash
# Process-level correctness and failure tests against the UNMODIFIED production binaries.
# Every process runs under a hard timeout. Prints PASS/FAIL per check; exits non-zero on any FAIL.
# Usage: scripts/failure_tests.sh            (after scripts/build.sh and `driver gen`)
set -u
cd "$(dirname "$0")/.."
W=../target/release/writer
R=../target/release/reader
RBX=./target/release/rbx
D=work/data
T=work/failtests
rm -rf "$T"; mkdir -p "$T"
export RUSTBRIDGE_KEY=$(openssl rand -hex 32)
OTHER_KEY=$(openssl rand -hex 32)
CH=/rbft$$
pass=0; fail=0

# NOTE: never background `t ...` when you need to kill the process: $! would be the subshell.
t() { perl -e '$t=shift; alarm $t; exec @ARGV or die "exec: $!"' "$@"; }   # hard timeout
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; fail=$((fail+1)); }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
seg() { $RBX shm-exists --channel "$1"; }

transfer() { # transfer <input> <output> [writer args...]; returns writer/reader exit codes in WX/RX
  local in=$1 out=$2; shift 2
  t 60 $R "$out" --channel $CH --timeout 10 >"$T/r.log" 2>&1 & local rp=$!
  t 60 $W "$in" --channel $CH "$@" >"$T/w.log" 2>&1; WX=$?
  wait $rp; RX=$?
}

echo "== payload edge cases (production writer/reader)"
for f in payload_0.bin payload_4096.bin payload_1000003.bin; do
  transfer $D/$f $T/out.bin
  check "$f: both exit 0 (writer=$WX reader=$RX)" '[ $WX -eq 0 ] && [ $RX -eq 0 ]'
  check "$f: sha256 matches" '[ "$(sha $D/$f)" = "$(sha $T/out.bin)" ]'
  rm -f $T/out.bin
done
printf 'x' > $T/one.bin
transfer $T/one.bin $T/out.bin
check "1-byte payload: sha256 matches" '[ $WX -eq 0 ] && [ "$(sha $T/one.bin)" = "$(sha $T/out.bin)" ]'

echo "== ring wraparound + backpressure (4 KiB ring, 1000-byte chunks, 1000003-byte payload)"
transfer $D/payload_1000003.bin $T/out.bin --ring-size 4096 --chunk-size 1000
check "tiny ring: exit 0 and sha256 matches" '[ $WX -eq 0 ] && [ $RX -eq 0 ] && [ "$(sha $D/payload_1000003.bin)" = "$(sha $T/out.bin)" ]'
check "segment unlinked after successful transfer" '[ "$(seg $CH)" = absent ]'
rm -f $T/out.bin
transfer $D/payload_4096.bin $T/out.bin --ring-size 4096 --chunk-size 4096
check "chunk larger than ring capacity is refused by writer" '[ $WX -ne 0 ] && grep -q "does not fit" $T/w.log'
pkill -f "reader $T/out.bin" 2>/dev/null; sleep 0.1

echo "== keys"
( unset RUSTBRIDGE_KEY; t 10 $W $D/payload_4096.bin --channel $CH ) >$T/w.log 2>&1; x=$?
check "writer without key exits non-zero with hint" '[ $x -ne 0 ] && grep -q "RUSTBRIDGE_KEY is not set" $T/w.log'
( unset RUSTBRIDGE_KEY; t 10 $R $T/out.bin --channel $CH --timeout 1 ) >$T/r.log 2>&1; x=$?
check "reader without key exits non-zero" '[ $x -ne 0 ] && grep -q "RUSTBRIDGE_KEY is not set" $T/r.log'
RUSTBRIDGE_KEY=abc t 10 $W $D/payload_4096.bin --channel $CH >$T/w.log 2>&1; x=$?
check "malformed key rejected" '[ $x -ne 0 ] && grep -q "hex characters" $T/w.log'

echo "== wrong key + destination preservation + cleanup"
echo "ORIGINAL DESTINATION CONTENT" > $T/dest.bin; before=$(sha $T/dest.bin)
t 30 $W $D/payload_16777216.bin --channel $CH >$T/w.log 2>&1 & wp=$!
RUSTBRIDGE_KEY=$OTHER_KEY t 30 $R $T/dest.bin --channel $CH --timeout 10 >$T/r.log 2>&1; rx=$?
wait $wp; wx=$?
check "reader with wrong key fails authentication" '[ $rx -ne 0 ] && grep -q "authentication failed" $T/r.log'
check "writer notices the reader detached and exits non-zero (no hang)" '[ $wx -ne 0 ] && [ $wx -ne 142 ] && grep -q "consumer detached" $T/w.log'
check "existing destination preserved byte-for-byte" '[ "$(sha $T/dest.bin)" = "$before" ]'
check "no .part file left behind" '[ ! -e $T/dest.part ]'
check "segment unlinked after failed transfer" '[ "$(seg $CH)" = absent ]'

echo "== early reader exit (reader SIGKILLed mid-stream)"
t 60 $W $D/payload_268435456.bin --channel $CH --ring-size 65536 --chunk-size 16384 >$T/w.log 2>&1 & wp=$!
sleep 0.2
$R $T/k.bin --channel $CH >$T/r.log 2>&1 & rp=$!
sleep 0.15; kill -9 $rp 2>/dev/null; wait $rp 2>/dev/null
wait $wp; wx=$?
check "writer exits non-zero after reader killed (exit=$wx, not timeout 142)" '[ $wx -ne 0 ] && [ $wx -ne 142 ] && grep -q "exited" $T/w.log'
check "segment unlinked after writer error exit" '[ "$(seg $CH)" = absent ]'
check "killed reader leaves only .part, never the final file" '[ ! -e $T/k.bin ]'
rm -f $T/k.part

echo "== writer termination (writer SIGKILLed mid-stream; 1 GiB so the kill lands mid-transfer)"
$W $D/payload_1073741824.bin --channel $CH --ring-size 65536 --chunk-size 16384 >$T/w.log 2>&1 & wp=$!
sleep 0.2
t 30 $R $T/wk.bin --channel $CH --timeout 10 >$T/r.log 2>&1 & rp=$!
sleep 0.15; kill -9 $wp 2>/dev/null; wait $wp 2>/dev/null
wait $rp; rx=$?
check "reader exits non-zero after writer killed (exit=$rx, not timeout 142)" '[ $rx -ne 0 ] && [ $rx -ne 142 ] && grep -q "producer (pid" $T/r.log'
check "no destination and no .part after writer killed" '[ ! -e $T/wk.bin ] && [ ! -e $T/wk.part ]'
check "killed writer leaves a stale segment (expected, documented)" '[ "$(seg $CH)" = exists ]'
t 60 $R $T/out.bin --channel $CH --timeout 10 >$T/r.log 2>&1 & rp=$!
sleep 0.3
t 60 $W $D/payload_1000003.bin --channel $CH >$T/w.log 2>&1; wx=$?; wait $rp; rx=$?
check "reader started first ignores stale segment; next transfer succeeds" '[ $wx -eq 0 ] && [ $rx -eq 0 ] && [ "$(sha $D/payload_1000003.bin)" = "$(sha $T/out.bin)" ]'
rm -f $T/out.bin

echo "== single consumer + argument validation"
t 30 $W $D/payload_268435456.bin --channel $CH --ring-size 65536 --chunk-size 16384 >$T/w.log 2>&1 & wp=$!
sleep 0.2
t 30 $R $T/a.bin --channel $CH >$T/r1.log 2>&1 & r1=$!
sleep 0.1
t 10 $R $T/b.bin --channel $CH --timeout 2 >$T/r2.log 2>&1; x=$?
check "second concurrent reader refused" '[ $x -ne 0 ] && grep -q "already attached" $T/r2.log'
wait $r1; wait $wp
check "first reader still completes correctly" '[ "$(sha $D/payload_268435456.bin)" = "$(sha $T/a.bin)" ]'
rm -f $T/a.bin
t 10 $W $D/payload_4096.bin --channel bad/name >$T/w.log 2>&1; x=$?
check "invalid channel name rejected" '[ $x -ne 0 ] && grep -q "shared memory name" $T/w.log'
t 10 $W $D/payload_4096.bin --channel /this_name_is_longer_than_31_bytes >$T/w.log 2>&1; x=$?
check "channel name over 31 bytes rejected" '[ $x -ne 0 ]'
t 10 $W $D/payload_4096.bin --channel $CH --ring-size 5000 >$T/w.log 2>&1; x=$?
check "non-power-of-two ring rejected" '[ $x -ne 0 ] && grep -q "power of two" $T/w.log'
t 10 $R $T/none.bin --channel /rbft_nobody_$$ --timeout 1 >$T/r.log 2>&1; x=$?
check "reader times out cleanly when no writer appears" '[ $x -ne 0 ] && [ $x -ne 142 ] && [ ! -e $T/none.bin ]'

echo
echo "summary: $pass passed, $fail failed"
[ $fail -eq 0 ]
