#!/usr/bin/env bash
# FdbWormhole — CWE-22 path traversal in FoundationDB backup/restore (fdbdecode --save)
set -uo pipefail
cd "$(dirname "$0")"

ZIG=/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig
BIN=exploit

# Compile the verbatim-transcribed vulnerable + fixed functions into one driver.
"$ZIG" c++ -std=c++20 -O1 -fno-sanitize=undefined exploit.cpp -o "$BIN"
rc=$?
if [ $rc -ne 0 ]; then
  echo "build failed (rc=$rc)"
  exit $rc
fi

./"$BIN"
rc=$?
echo "exit_code=$rc"
exit $rc
