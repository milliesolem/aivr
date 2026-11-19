#!/usr/bin/env bash
# RocksGhost — build + run the differential PoC for the RocksDB ForwardIterator
# use-after-free (fix #15704, unreleased) against a faithful C++ transcription of
# the vulnerable/fixed reference-counting logic, using a poisoned deterministic
# arena so the use-after-free is observable without AddressSanitizer.
set -u
cd "$(dirname "$0")"

ZIG="${ZIG:-/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig}"
CXXFLAGS="-std=c++17 -O1"

mkdir -p build

echo "== [1/2] building (zig cc) =="
"$ZIG" c++ $CXXFLAGS poc.cc -o build/poc || { echo "BUILD FAILED"; exit 1; }

echo
echo "== [2/2] run =="
./build/poc
rc=$?
echo
echo "poc exit=$rc"
exit 0
