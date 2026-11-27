#!/bin/sh
# Build the LevelOverrun PoC: compile the REAL vendored leveldb block decoder
# twice — once with the vulnerable DecodeEntry check, once with the fixed one —
# plus the harness. No system compiler needed; uses zig cc (links glibc).
set -e
cd "$(dirname "$0")"

ZIG=/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig
if [ ! -x "$ZIG" ]; then ZIG="$(command -v zig || true)"; fi
if [ -z "$ZIG" ]; then echo "need zig (C/C++ compiler)"; exit 1; fi

L=leveldb
OUT=/tmp/opencode/levoverrun
mkdir -p "$OUT"

# The vendored block.cc carries the FIXED two-step check. Derive the vulnerable
# variant by reverting exactly those lines to the single, overflow-prone check
# (leveldb <= 1.23 / pre-29465588d3).
python3 - "$L/table/block.cc" "$OUT/block_vuln.cc" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
t = open(src).read()
fixed = ("  if (static_cast<uint32_t>(limit - p) < *non_shared ||\n"
         "      static_cast<uint32_t>(limit - p) - *non_shared < *value_length) {\n")
vuln  = "  if (static_cast<uint32_t>(limit - p) < (*non_shared + *value_length)) {\n"
assert fixed in t, "fixed check not found in vendored block.cc"
open(dst, "w").write(t.replace(fixed, vuln))
PY

COMMON="util/coding.cc util/comparator.cc util/status.cc util/logging.cc table/iterator.cc"
CFLAGS="-std=c++17 -O1 -DLEVELDB_PLATFORM_POSIX -I$L -I$L/include"

# fixed build (real vendored block.cc)
"$ZIG" c++ $CFLAGS poc.cc "$L/table/block.cc" $(echo $COMMON | sed "s#\([a-z]*/\)#$L/\1#g") -o "$OUT/poc_fixed"
# vulnerable build (reverted DecodeEntry)
"$ZIG" c++ $CFLAGS poc.cc "$OUT/block_vuln.cc" $(echo $COMMON | sed "s#\([a-z]*/\)#$L/\1#g") -o "$OUT/poc_vuln"
echo "built $OUT/poc_vuln and $OUT/poc_fixed"
