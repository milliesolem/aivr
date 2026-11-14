#!/usr/bin/env bash
# MagickOverrun — ImageMagick ShearRotateImage / XShearImage heap
# out-of-bounds WRITE (CWE-787). GHSA-8xm2-q8hq-m68q, fixed upstream by
# commit 1360d45 (unreleased as of ImageMagick 7.1.2-35).
#
# Builds the verbatim-extracted vulnerable XShearImage "RIGHT" pixel-transfer
# loop (vendor/shear.c, copied from MagickCore/shear.c @ 1360d45~1) with the
# zig toolchain, then runs a differential: the pre-fix loop writes past the
# end of the pixel row (canary clobbered), the fixed loop's up-front guard
# skips the row (canary intact).
#
# exit 0 = OOB write reproduced on the vulnerable path AND contained on the
#          fixed path (differential proof).  Any other outcome -> non-zero.
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

echo "=== build harness against the verbatim-extracted shear.c loop ==="
timeout 120 "$ZIG" cc -O1 -std=c11 -Wall -Wextra -o "$WORK/magick" exploit.c \
  || { echo "build failed"; exit 2; }

echo
OUT="$("$WORK/magick" 2>&1)"
RC=$?
echo "$OUT"

if [ "$RC" -eq 0 ] && echo "$OUT" | grep -q "MAGICKOVERRUN-OK"; then
  echo
  echo "MAGICKOVERRUN-OK: vulnerable path overruns the pixel row (CWE-787 OOB write), fixed path contains it."
  exit 0
fi
echo "MAGICKOVERRUN-FAIL: unexpected exit code or missing marker (rc=$RC)"
exit 1
