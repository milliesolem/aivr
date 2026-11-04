#!/usr/bin/env bash
# Reproduce UltraPickle (ultralytics torch_load weights_only=False deser RCE).
set -e
cd "$(dirname "$0")"
rm -f /tmp/opencode/ultrapickle_PWNED
python3 poc.py
