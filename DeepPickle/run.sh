#!/usr/bin/env bash
# Reproduce DeepPickle (google-deepmind/ai-foundations pickle deser RCE).
set -e
cd "$(dirname "$0")"
rm -f /tmp/opencode/deepickle_PWNED
python3 poc.py
