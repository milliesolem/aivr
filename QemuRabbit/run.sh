#!/bin/bash
# QemuRabbit — QEMU virtio-snd guest->host memory exhaustion (0-day, no CVE)
# Compiles the verbatim vulnerable/fixed buffer-size validation with the zig C
# toolchain and runs the differential.
set -uo pipefail
cd "$(dirname "$0")"

ZIG="${ZIG:-/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig}"
if [ ! -x "$ZIG" ]; then
  echo "[!] zig not found at $ZIG (set ZIG=...)" >&2
  exit 2
fi

OUT="${TMPDIR:-/tmp/opencode}/qemurabbit"
"$ZIG" cc -O1 -o "$OUT" exploit.c || { echo "[!] compile failed" >&2; exit 1; }
exec "$OUT"
