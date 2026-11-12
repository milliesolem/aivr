#!/usr/bin/env bash
# TunnelPicklock — build + run (pure Go, stdlib only).
set -u
cd "$(dirname "$0")"

GO="${GO:-}"
if [ -z "$GO" ]; then GO="$(command -v go)"; fi
if [ -z "$GO" ] || [ ! -x "$GO" ]; then echo "NO GO TOOLCHAIN — install go or set GO" >&2; exit 3; fi

echo "building with: $GO ($($GO version | awk '{print $3}'))"
GOTOOLCHAIN=local GOFLAGS=-mod=mod GO111MODULE=off "$GO" run poc.go
exit $?
