#!/usr/bin/env bash
# JqMimic — reproduce jq 1.8.2 raw-NUL numeric-token truncation.
# Offline: the official jq 1.8.2 static Linux binary is bundled and SHA-256 checked.
set -u
cd "$(dirname "$0")"

EXPECT_SHA=b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f
if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum not available; refusing to run unpinned binary" >&2
  exit 2
fi
GOT_SHA=$(sha256sum jq-1.8.2 | awk '{print $1}')
if [ "$GOT_SHA" != "$EXPECT_SHA" ]; then
  echo "jq-1.8.2 checksum mismatch: $GOT_SHA" >&2
  exit 2
fi

exec python3 poc.py
