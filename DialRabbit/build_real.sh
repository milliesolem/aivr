#!/bin/bash
# DialRabbit — OPTIONAL end-to-end verification (≈10 min on 2 cores).
#
# Builds the REAL libphonenumber C++ library twice — vulnerable (v9.0.43
# sources, commit 28bcf76) and fixed (981600c) — together with the protobuf
# 3.21.12 runtime and abseil 20220623, all compiled with zig cc (libc++ ABI),
# then calls PhoneNumberUtil::Parse() on the RFC3966 ReDoS payload and prints
# the timing for both builds.
#
# Dependencies: zig, cmake (+ninja) as shipped in ./toolchain, micromamba, git,
# network access for protobuf/abseil/libphonenumber sources. Override WORK to
# use a different scratch directory.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-/tmp/opencode/dialrabbit}
ZIG=${ZIG:-/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig}
CMAKE=${CMAKE:-/home/millie/tools/toolchain/cmake-3.29.3-linux-x86_64/bin/cmake}
NINJA_DIR=${NINJA_DIR:-/home/millie/tools/toolchain/ninja_bin}
MM=${MM:-/home/millie/tmp/bin/micromamba}
export PATH="$NINJA_DIR:$PATH"
mkdir -p "$WORK"
cd "$WORK"
printf '#!/bin/sh\nexec %s c++ "$@"\n' "$ZIG" > zigcpp.sh
printf '#!/bin/sh\nexec %s cc "$@"\n' "$ZIG" > zigcc.sh
chmod +x zigcpp.sh zigcc.sh

# 1. prebuilt protobuf/abseil/icu headers + protoc (APIs only; runtimes rebuilt)
if [ ! -x env/bin/protoc ]; then
  "$MM" create -y -p "$WORK/env" -c conda-forge --override-channels \
    libprotobuf abseil-cpp icu >/dev/null
fi

# 2. protobuf runtime built with zig (libc++), so it links against our objects
if [ ! -f build-pb/libprotobuf.a ]; then
  [ -d protobuf-3.21.12 ] || {
    curl -sL -m 60 -o pb.tar.gz \
      https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protobuf-cpp-3.21.12.tar.gz
    tar xzf pb.tar.gz; }
  "$CMAKE" -S protobuf-3.21.12 -B build-pb -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$WORK/zigcc.sh" \
    -DCMAKE_CXX_COMPILER="$WORK/zigcpp.sh" -Dprotobuf_BUILD_TESTS=OFF \
    -Dprotobuf_BUILD_PROTOC_BINARIES=OFF -Dprotobuf_WITH_ZLIB=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE >/dev/null
  ninja -C build-pb -j2 libprotobuf >/dev/null
fi

# 3. abseil runtime built with zig (same lts_20220623 API as the headers)
if [ -z "$(find build-absl -name 'libabsl_strings.a' 2>/dev/null)" ]; then
  [ -d abseil-cpp-20220623.0 ] || {
    curl -sL -m 60 -o absl.tar.gz \
      https://github.com/abseil/abseil-cpp/archive/refs/tags/20220623.0.tar.gz
    tar xzf absl.tar.gz; }
  "$CMAKE" -S abseil-cpp-20220623.0 -B build-absl -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$WORK/zigcc.sh" \
    -DCMAKE_CXX_COMPILER="$WORK/zigcpp.sh" -DCMAKE_CXX_STANDARD=17 \
    -DABSL_BUILD_TESTING=OFF -DABSL_ENABLE_INSTALL=OFF \
    -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE >/dev/null
  ninja -C build-absl -j2 >/dev/null
fi
ABSL_LIBS=$(find build-absl -name '*.a' | tr '\n' ' ')

# 4. libphonenumber source at the vulnerable and fixed commits
if [ ! -d lp/.git ]; then
  git clone --depth 60 https://github.com/google/libphonenumber lp
fi
for spec in "lpv 28bcf76" "lpf 981600cc587fb87483ad294a61daa187afc64b2c"; do
  set -- $spec
  [ -d "$1/cpp" ] || git -C lp worktree add "$WORK/$1" "$2"
done

build_lib() {  # $1 = source worktree, $2 = build dir
  "$CMAKE" -S "$1/cpp" -B "$2" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$WORK/zigcc.sh" \
    -DCMAKE_CXX_COMPILER="$WORK/zigcpp.sh" \
    -DCMAKE_PREFIX_PATH="$WORK/env" -DUSE_ICU_REGEXP=ON \
    -DUSE_PROTOBUF_LITE=OFF -DUSE_BOOST=OFF -DUSE_STDMUTEX=ON \
    -DBUILD_TESTING=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE >/dev/null
  ninja -C "$2" -j2 phonenumber >/dev/null
}

link_driver() {  # $1 = libphonenumber.a, $2 = output
  "$ZIG" c++ -std=c++17 -O2 -w -I "$WORK/lpv/cpp/src" -I "$WORK/env/include" \
    "$HERE/real_parse.cc" -Wl,--start-group "$1" build-pb/libprotobuf.a \
    $ABSL_LIBS -Wl,--end-group -L"$WORK/env/lib" -Wl,-rpath,"$WORK/env/lib" \
    -licui18n -licuuc -licudata -lpthread -o "$2"
}

echo "[1/4] building vulnerable libphonenumber.a (28bcf76) ..."
build_lib "$WORK/lpv" "$WORK/build-lpv"
echo "[2/4] building fixed libphonenumber.a (981600c) ..."
build_lib "$WORK/lpf" "$WORK/build-lpf"
echo "[3/4] linking drivers ..."
link_driver "$WORK/build-lpv/libphonenumber.a" "$WORK/real_parse_vuln"
link_driver "$WORK/build-lpf/libphonenumber.a" "$WORK/real_parse_fixed"
echo "[4/4] running PhoneNumberUtil::Parse() on tel:253-0000;phone-context=(aa.){30}aa!"
echo "--- vulnerable build (expect: killed after 15 s) ---"
"$WORK/real_parse_vuln" 30 15000
echo "--- fixed build (expect: returns in <1 ms, NOT_A_NUMBER) ---"
"$WORK/real_parse_fixed" 30 15000
