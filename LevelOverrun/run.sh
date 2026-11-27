#!/bin/sh
# Build + run the LevelOverrun PoC against the real vendored leveldb block decoder.
set -e
cd "$(dirname "$0")"
sh build.sh >/dev/null
echo "=== VULNERABLE (leveldb <= 1.23 / pre-29465588d3) ==="
/tmp/opencode/levoverrun/poc_vuln VULNERABLE
echo
echo "=== FIXED (leveldb 29465588d3) ==="
/tmp/opencode/levoverrun/poc_fixed FIXED
