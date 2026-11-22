#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export GOTOOLCHAIN=local
export GOFLAGS=-mod=mod
export GOPROXY=off
exec go run poc.go
