#!/usr/bin/env bash
# Build redis-server for the vulnerable (8.10.3) and fixed (9a5c6e9) commits.
set -uo pipefail
cd "$(dirname "$0")"

MUSL_CC="/home/millie/tools/toolchain/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc"
WORK="${WORK:-/home/millie/tmp/redis-oob}"
mkdir -p "$WORK"
cd "$WORK"

echo "[*] cloning redis (blob:none, single branch unstable + 8.10) ..."
if [ ! -d redis/.git ]; then
  timeout 300 git clone --filter=blob:none --no-checkout https://github.com/redis/redis.git redis 2>&1 | tail -2
fi

build() {
  local ref="$1" out="$2"
  if [ -f "$out/src/redis-server" ]; then echo "[*] $out already built"; return; fi
  echo "[*] building redis-server @ $ref -> $out"
  rm -rf "$out"
  git -C redis checkout -f "$ref" 2>/dev/null || git -C redis checkout -f "origin/$ref" 2>/dev/null
  # materialize a clean worktree copy
  git -C redis archive "$ref" | tar -x -C /tmp/ 2>/dev/null && true
  # simpler: use a separate worktree-free copy via archive
  mkdir -p "$out"
  git -C redis archive "$ref" | tar -x -C "$out"
  ( cd "$out" && timeout 600 make -C src -j"$(nproc)" redis-server MALLOC=libc CC="$MUSL_CC" LDFLAGS=-static V=0 >build.log 2>&1 )
  if [ -f "$out/src/redis-server" ]; then echo "[*] built $out/src/redis-server"; else echo "[!] BUILD FAILED for $out (see $out/build.log)"; fi
}

# 8.10.3 is the newest stable; the OOB fix 9a5c6e9 is only on unstable.
build 8.10.3 vuln
build 9a5c6e97884e fixed

ls -la "$WORK"/vuln/src/redis-server "$WORK"/fixed/src/redis-server 2>&1
