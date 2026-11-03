#!/bin/bash
# FumbleFactor — reproduce the weak-2FA brute-force bypass and show the fix blocks it.
# No network, no third-party deps (python3 stdlib only). Exit 0 on success.
set -euo pipefail
cd "$(dirname "$0")"
python3 vuln_demo.py
