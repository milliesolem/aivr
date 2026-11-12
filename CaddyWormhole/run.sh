#!/usr/bin/env bash
# CaddyWormhole — path-guard bypass in Caddy's rewrite handler (real exploit PoC).
#
# Single entrypoint. Builds the real vulnerable + fixed Caddy binaries if they are
# not already cached (build.sh), then runs exploit.py, which spins up the REAL
# caddy server, drives it with the traversal payloads, and asserts the bypass.
set -u
cd "$(dirname "$0")"

CACHE="${AIVR_CADDY_CACHE:-/home/millie/tmp/aivr-caddy}"
VULN="$CACHE/caddy-vuln.bin"
FIXED="$CACHE/caddy-fixed.bin"

if [ ! -x "$VULN" ] || [ ! -x "$FIXED" ]; then
  echo "[run] binaries not cached — building (needs network on first run)"
  bash build.sh || { echo "RESULT: build failed"; exit 3; }
fi

exec python3 exploit.py --vuln "$VULN" --fixed "$FIXED"
