#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
ZIG="/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig"
if [ ! -x ./poc ]; then
  "$ZIG" c++ -O2 -o poc poc.cc
fi
./poc
