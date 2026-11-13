#!/bin/bash
# DeltaOverrun — google/leveldb DecodeEntry integer overflow -> OOB read
# (CWE-190 -> CWE-125). Faithful reproduction of the vulnerable/fixed
# table/block.cc DecodeEntry compiled with zig c++.
set -e
cd "$(dirname "$0")"

ZIG="${ZIG:-/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0}"
export PATH="$ZIG:$PATH"

BIN=/tmp/opencode/deltaoverrun_exploit
zig c++ -O2 -o "$BIN" exploit.cc
"$BIN"
