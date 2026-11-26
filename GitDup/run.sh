#!/usr/bin/env bash
# Build and run the vulnerable GitDup PoC (aborts with a glibc double-free), then the fixed one.
set -e
cd "$(dirname "$0")"
bash build.sh
echo "=== VULNERABLE ==="
./poc || true
echo "=== FIXED ==="
./poc fixed
