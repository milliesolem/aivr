#!/usr/bin/env bash
# Build + run the CurlEcho curl header-terminator validation-bypass PoC (stdlib only).
set -euo pipefail
cd "$(dirname "$0")"

CC=""
for c in /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig cc gcc clang; do
  if command -v "$c" >/dev/null 2>&1; then CC="$c"; break; fi
done
if [ -z "$CC" ]; then echo "no C compiler found" >&2; exit 2; fi

if [[ "$CC" == *zig* ]]; then
  "$CC" cc poc.c -o poc
else
  "$CC" poc.c -o poc
fi

./poc
