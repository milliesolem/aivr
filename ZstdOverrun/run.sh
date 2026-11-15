#!/usr/bin/env bash
# ZstdOverrun — out-of-bounds write in zstd's recursive block splitter (CWE-787).
#
# ZSTD_deriveBlockSplitsHelper() writes split positions into
# ZSTD_blockSplitCtx.partitions[] (ZSTD_MAX_NB_BLOCK_SPLITS == 196 U32 entries),
# and only checks the split budget on function entry. A left-child recursion can
# fill the whole array before its ancestors write their own split positions, so
# `splits->splitLocations[splits->idx] = midIdx` (and the terminator write of
# nbSeq) runs past partitions[] into the adjacent `entropyMetadata` field.
#
# Both binaries are the REAL libzstd (facebook/zstd), compiled from source with
# musl-gcc. The ONLY change from upstream is a canary field placed immediately
# after partitions[] in ZSTD_blockSplitCtx so the out-of-bounds WRITE is detected
# deterministically (ASAN is unavailable):
#   - zstd-vuln : v1.5.7  (the latest release, 2025-02-18) — vulnerable
#   - zstd-fixed: commit 974238ca (the upstream fix, 2026-11-10) — re-checks the
#                 budget after the left recursion and adds one extra slot
#
# A single crafted external sequence stream (38,400 valid 3-byte matches over a
# 128,000-byte all-zero source) deterministically exhausts the 196-split budget.
set -u
cd "$(dirname "$0")"

VULN=./zstd-vuln
FIXED=./zstd-fixed

# Rebuild the binaries from source if absent (needs the local toolchain).
if [ ! -x "$VULN" ] || [ ! -x "$FIXED" ]; then
  echo "[*] binaries missing — building from zstd source via build.sh"
  bash build.sh || { echo "build failed"; exit 1; }
fi

echo "=== [1/2] VULNERABLE — zstd v1.5.7 (latest release) ==="
"$VULN"
VC=$?
echo "    [vuln binary exit code: $VC]"

echo
echo "=== [2/2] FIXED — zstd commit 974238ca (unreleased) ==="
"$FIXED"
FC=$?
echo "    [fixed binary exit code: $FC]"

echo
# The exploit marker (from the vulnerable binary) must appear, and the fixed
# binary must report the canary intact.
if grep -q "ZSTDOVERRUN-CANARY-CLOBBERED" <<<"$( "$VULN" 2>&1 )" \
   && grep -q "ZSTDOVERRUN-CANARY-INTACT" <<<"$( "$FIXED" 2>&1 )"; then
  echo "RESULT: ZstdOverrun CONFIRMED — vuln writes past partitions[196] (canary clobbered), fixed does not"
  exit 0
else
  echo "RESULT: ZstdOverrun NOT confirmed"
  exit 1
fi
