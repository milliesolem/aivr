#!/bin/bash
# CrabRabbit PoC — pingora response decompression bomb (CWE-770/409)
set -e
cd "$(dirname "$0")"
echo "=== CrabRabbit: pingora decompression bomb (faithful Python port) ==="
python3 poc.py --ratio 800
