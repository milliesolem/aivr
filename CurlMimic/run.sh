#!/usr/bin/env bash
# CurlMimic — curl zstd content decoder accepts truncated streams (gzip rejects).
#
# Differential against a REAL curl built with zstd + zlib:
#   truncated Content-Encoding: gzip  -> exit 61 "Gzip stream ended before completion" (REJECT)
#   truncated Content-Encoding: zstd  -> exit 0 + partial decompressed data written (ACCEPT, bug)
set -u
cd "$(dirname "$0")"

# --- 1. get a curl with zstd+zlib (cached build via zig cc) -----------------
CURL_BIN="$(bash build.sh | tail -1)"
if [ ! -x "$CURL_BIN" ]; then
  echo "[-] could not obtain a curl binary"; exit 2
fi
echo "[*] curl: $CURL_BIN"

# --- 2. python env with zstandard for the test server -----------------------
PY="${PYTHON:-python3}"
"$PY" -c "import zstandard" 2>/dev/null || {
  VENV=/tmp/opencode/curl-mimic/venv
  if [ ! -x "$VENV/bin/python" ]; then "$PY" -m venv "$VENV" || exit 2; fi
  "$VENV/bin/pip" install --quiet zstandard 2>/dev/null
  PY="$VENV/bin/python"
}

# --- 3. start the truncated-response server ---------------------------------
PORT=18888
"$PY" serve.py >/tmp/opencode/curl-mimic-server.log 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null' EXIT
for _ in $(seq 1 40); do
  curl -s --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/__health" 2>/dev/null && break
  sleep 0.25
done
cat /tmp/opencode/curl-mimic-server.log

# --- 4. differential test ---------------------------------------------------
GZIP_OUT=/tmp/opencode/curl-mimic-gzip.out
ZSTD_OUT=/tmp/opencode/curl-mimic-zstd.out
rm -f "$GZIP_OUT" "$ZSTD_OUT"

echo ""
echo "== truncated Content-Encoding: gzip =="
"$CURL_BIN" -sS --compressed --max-time 10 -o "$GZIP_OUT" "http://127.0.0.1:$PORT/gzip" -w "exit=%{exitcode} size=%{size_download}\n" 2>&1
GZIP_RC=$?
echo "   (curl rc=$GZIP_RC)"

echo ""
echo "== truncated Content-Encoding: zstd =="
"$CURL_BIN" -sS --compressed --max-time 10 -o "$ZSTD_OUT" "http://127.0.0.1:$PORT/zstd" -w "exit=%{exitcode} size=%{size_download}\n" 2>&1
ZSTD_RC=$?
echo "   (curl rc=$ZSTD_RC, output bytes: $(wc -c < "$ZSTD_OUT" 2>/dev/null || echo 0))"

# --- 5. verdict -------------------------------------------------------------
echo ""
echo "==================== VERDICT ===================="
gzip_rejected=0; zstd_accepted=0
if [ "$GZIP_RC" -ne 0 ]; then gzip_rejected=1; fi
if [ "$ZSTD_RC" -eq 0 ]; then zstd_accepted=1; fi

if [ "$gzip_rejected" = "1" ] && [ "$zstd_accepted" = "1" ]; then
  echo "[+] PASS: truncated gzip is REJECTED (rc=$GZIP_RC), but truncated zstd is"
  echo "    silently ACCEPTED (rc=$ZSTD_RC, partial data written). CurlMimic CONFIRMED."
  exit 0
fi
echo "[-] FAIL: expected gzip=reject / zstd=accept, got gzip_rc=$GZIP_RC zstd_rc=$ZSTD_RC"
exit 1
