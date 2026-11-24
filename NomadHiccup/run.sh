#!/usr/bin/env bash
# Reproduce NomadHiccup. Exit 0 on successful demonstration.
set -e
cd "$(dirname "$0")"
GOTOOLCHAIN=local GOFLAGS=-mod=mod go run poc.go
