#!/bin/bash
# DialRabbit — run the ReDoS PoC against the REAL libphonenumber C++ ICU regexp
# adapter (vendored from release v9.0.43). Exit 0 == vulnerable behaviour shown.
set -e
cd "$(dirname "$0")"

ZIG=${ZIG:-/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig}
[ -x "$ZIG" ] || ZIG=$(command -v zig)

# ICU headers + libs: env override, local conda pkg, then system.
for p in "$ICU_PREFIX" \
         /home/millie/.local/share/mamba/pkgs/https/conda.anaconda.org/conda-forge/linux-64/icu-78.3-py310h44b86e0_2 \
         /usr/local /usr; do
  if [ -n "$p" ] && [ -f "$p/include/unicode/regex.h" ] && [ -e "$p/lib/libicui18n.so" -o -e "$p/lib/x86_64-linux-gnu/libicui18n.so" ]; then
    ICU_PREFIX=$p
    break
  fi
done
if [ -z "$ICU_PREFIX" ] && [ -f /usr/include/unicode/regex.h ]; then ICU_PREFIX=/usr; fi
if [ -z "$ICU_PREFIX" ]; then
  echo "FATAL: ICU development headers (unicode/regex.h) not found; set ICU_PREFIX" >&2
  exit 2
fi
ICU_LIBDIR=$ICU_PREFIX/lib
[ -d "$ICU_LIBDIR" ] || ICU_LIBDIR=$ICU_PREFIX/lib/x86_64-linux-gnu

echo "[build] zig c++ via $ZIG"
"$ZIG" c++ -std=c++17 -O2 -I src -I "$ICU_PREFIX/include" \
  redos.cc \
  src/phonenumbers/regexp_adapter_icu.cc \
  src/phonenumbers/string_byte_sink.cc \
  src/phonenumbers/default_logger.cc \
  src/phonenumbers/logger.cc \
  -L "$ICU_LIBDIR" -Wl,-rpath,"$ICU_LIBDIR" \
  -licui18n -licuuc -licudata -o redos

echo "[run] ./redos"
./redos
