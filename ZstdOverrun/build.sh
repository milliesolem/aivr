#!/usr/bin/env bash
# Rebuild zstd-vuln / zstd-fixed from upstream facebook/zstd source.
#
#   zstd-vuln  : tag v1.5.7  (latest release)  — vulnerable
#   zstd-fixed : commit 974238ca (2026-11-10)  — fixed upstream
#
# The only local modification to the library is the AIVR canary: an 8-word field
# inserted immediately after `partitions[]` in ZSTD_blockSplitCtx (see
# lib/compress/zstd_compress_internal.h), so the OOB write past partitions[196]
# is detected deterministically without ASAN.
set -eu
cd "$(dirname "$0")"

MUSL=${MUSL:-/home/millie/tools/toolchain/x86_64-linux-musl-cross}
CC="$MUSL/bin/x86_64-linux-musl-gcc"
ZSTD_REPO=${ZSTD_REPO:-/home/millie/tmp/ffscan/zstd}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

if [ ! -d "$ZSTD_REPO/.git" ]; then
  echo "[*] cloning facebook/zstd (depth 200)..."
  git clone --quiet --filter=blob:none --depth 200 https://github.com/facebook/zstd.git "$WORK/zstd"
  ZSTD_REPO="$WORK/zstd"
  git -C "$ZSTD_REPO" fetch --quiet --depth 1 origin refs/tags/v1.5.7:refs/tags/v1.5.7 || true
fi

echo "[*] extracting sources..."
mkdir -p "$WORK/vuln" "$WORK/fixed"
git -C "$ZSTD_REPO" archive v1.5.7   | tar -x -C "$WORK/vuln"
git -C "$ZSTD_REPO" archive 974238ca | tar -x -C "$WORK/fixed"

# AIVR canary instrumentation (identical in both trees).
python3 - <<'PY'
import re
for name in ("vuln", "fixed"):
    p = f"$WORK/{name}/lib/compress/zstd_compress_internal.h"
    s = open(p).read()
    if "AIVR instrumentation" not in s:
        s = s.replace(
            "    U32 partitions[ZSTD_MAX_NB_BLOCK_SPLITS];\n",
            "    U32 partitions[ZSTD_MAX_NB_BLOCK_SPLITS];\n"
            "    U32 canary[8]; /* AIVR instrumentation: detects the OOB write past partitions[] */\n", 1)
        s = s.replace(
            "    U32 partitions[ZSTD_MAX_NB_BLOCK_SPLITS + 1]; /* splits, followed by the end of the block */\n",
            "    U32 partitions[ZSTD_MAX_NB_BLOCK_SPLITS + 1]; /* splits, followed by the end of the block */\n"
            "    U32 canary[8]; /* AIVR instrumentation: detects the OOB write past partitions[] */\n", 1)
    open(p, "w").write(s)
PY

echo "[*] building libzstd.a (vuln + fixed)..."
make -C "$WORK/vuln/lib"  libzstd.a CC="$CC" MOREFLAGS="-O1 -g0" -j4 >/dev/null 2>&1
make -C "$WORK/fixed/lib" libzstd.a CC="$CC" MOREFLAGS="-O1 -g0" -j4 >/dev/null 2>&1

echo "[*] compiling drivers..."
"$CC" -O1 -I "$WORK/vuln/lib"  -I "$WORK/vuln/lib/common"  -I "$WORK/vuln/lib/compress"  driver.c "$WORK/vuln/lib/libzstd.a"  -o zstd-vuln  -static -lpthread
"$CC" -O1 -I "$WORK/fixed/lib" -I "$WORK/fixed/lib/common" -I "$WORK/fixed/lib/compress" driver.c "$WORK/fixed/lib/libzstd.a" -o zstd-fixed -static -lpthread

chmod +x zstd-vuln zstd-fixed
echo "[*] done — built ./zstd-vuln and ./zstd-fixed"
