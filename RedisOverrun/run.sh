#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")"

VULN_BIN="${VULN_BIN:-/home/millie/tmp/redis-oob/vuln/src/redis-server}"
FIXED_BIN="${FIXED_BIN:-/home/millie/tmp/redis-oob/fixed/src/redis-server}"

# Build the real redis-server (vuln 8.10.3 + fixed 9a5c6e9) if not already built.
# (The binaries are pre-built in /home/millie/tmp/redis-oob; build.sh is the
# networked fallback for a fresh checkout.)
if [ ! -f "$VULN_BIN" ] || [ ! -f "$FIXED_BIN" ]; then
  echo "[*] redis-server binaries missing; running build.sh (needs network) ..."
  bash build.sh || { echo "build failed"; exit 2; }
fi

echo "[*] driving the real redis-server (vuln vs fixed) with a crafted cluster-bus MEET packet ..."
VULN_BIN="$VULN_BIN" FIXED_BIN="$FIXED_BIN" timeout 120 python3 exploit.py
