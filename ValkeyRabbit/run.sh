#!/usr/bin/env bash
# ValkeyRabbit — valkey script-debugger partial-read assert -> whole-server SIGABRT.
set -u
cd "$(dirname "$0")"

MARKER="VALKEY-RABBIT-CONFIRMED"

CC="${CC:-}"
if [ -z "$CC" ]; then
  if command -v cc >/dev/null 2>&1; then CC="cc";
  elif command -v gcc >/dev/null 2>&1; then CC="gcc";
  elif [ -x /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig ]; then CC="/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig cc";
  elif [ -x /home/millie/tools/toolchain/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc ]; then CC="/home/millie/tools/toolchain/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc -static";
  else echo "ERROR: no C compiler found" >&2; exit 1; fi
fi

BIN="/tmp/opencode/valkeyrabbit_$$"
trap 'rm -f "$BIN"' EXIT
$CC -O0 -o "$BIN" valkeyrabbit.c || { echo "ERROR: compile failed" >&2; exit 1; }

OUT="$("$BIN" 2>&1)"
echo "$OUT"
if printf '%s' "$OUT" | grep -q "RESULT: $MARKER"; then exit 0; fi
exit 1
