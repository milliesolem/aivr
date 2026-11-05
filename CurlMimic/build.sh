#!/usr/bin/env bash
# Build a curl with zstd + zlib support using the zig C toolchain (no system cc).
# Caches the result at /tmp/opencode/curl-mimic/ so repeated runs are fast.
set -euo pipefail

ZIG=/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig
CMAKE_DIR=/home/millie/tools/toolchain/cmake-3.29.3-linux-x86_64
WORK=/tmp/opencode/curl-mimic
CURL_BIN="$WORK/curl/build/src/curl"

if [ -x "$CURL_BIN" ]; then
  echo "[*] using cached curl: $CURL_BIN"
  echo "$CURL_BIN"
  exit 0
fi

echo "[*] building curl with zstd+zlib (zig cc) — first run takes a few minutes"
mkdir -p "$WORK" "$WORK/bin"

# wrapper scripts for the zig toolchain
cat > "$WORK/bin/zig-cc" <<'EOF'
#!/usr/bin/env bash
exec /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig cc "$@"
EOF
cat > "$WORK/bin/zig-cxx" <<'EOF'
#!/usr/bin/env bash
exec /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig c++ "$@"
EOF
cat > "$WORK/bin/zig-ar" <<'EOF'
#!/usr/bin/env bash
exec /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig ar "$@"
EOF
cat > "$WORK/bin/zig-ranlib" <<'EOF'
#!/usr/bin/env bash
exec /home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig ar s "$@"
EOF
chmod +x "$WORK/bin/"*

# download + build zstd and zlib
cd "$WORK"
if [ ! -f zstd/lib/libzstd.a ] || [ ! -f zlib/libz.a ]; then
  [ ! -d zstd ] && git clone --quiet --depth 1 https://github.com/facebook/zstd.git
  [ ! -d zlib ] && git clone --quiet --depth 1 https://github.com/madler/zlib.git
  export CC="$ZIG cc"; export AR="$ZIG ar"; export RANLIB="true"
  [ ! -f zstd/lib/libzstd.a ] && ( cd zstd/lib && make -j4 libzstd.a >/dev/null 2>&1 )
  [ ! -f zlib/libz.a ] && ( cd zlib && ./configure --static >/dev/null 2>&1 && make -j4 libz.a >/dev/null 2>&1 )
  unset CC AR RANLIB
fi
ls -la zstd/lib/libzstd.a zlib/libz.a

# download + build curl
if [ ! -x "$CURL_BIN" ]; then
  rm -rf curl
  git clone --quiet --depth 400 https://github.com/curl/curl.git
  ( cd curl && git checkout 116c5ae0f58025f25eebb9c3197513f022263e98 2>/dev/null || true )
  mkdir -p curl/build
  (
    cd curl/build
    export PATH="$WORK/bin:$CMAKE_DIR/bin:$PATH"
    cmake .. \
      -DCMAKE_C_COMPILER=zig-cc \
      -DCMAKE_CXX_COMPILER=zig-cxx \
      -DCMAKE_AR="$WORK/bin/zig-ar" \
      -DCMAKE_RANLIB="$WORK/bin/zig-ranlib" \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INCLUDE_PATH="$WORK/zstd/lib;$WORK/zlib" \
      -DCMAKE_LIBRARY_PATH="$WORK/zstd/lib;$WORK/zlib" \
      -DBUILD_SHARED_LIBS=OFF \
      -DBUILD_CURL_EXE=ON \
      -DCURL_ZSTD=ON -DCURL_ZLIB=ON -DCURL_BROTLI=OFF \
      -DCURL_USE_OPENSSL=OFF -DCURL_USE_SCHANNEL=OFF \
      -DCURL_USE_LIBSSH2=OFF -DCURL_USE_LIBPSL=OFF \
      -DZSTD_USE_STATIC_LIBS=ON \
      -DBUILD_TESTING=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF \
      -DCURL_DISABLE_LDAP=ON -DCURL_DISABLE_LDAPS=ON \
      >/dev/null 2>&1
    make -j4 >/dev/null 2>&1
  )
fi

if [ ! -x "$CURL_BIN" ]; then
  echo "[-] curl build failed" >&2
  exit 1
fi
echo "[*] built: $CURL_BIN"
"$CURL_BIN" --version | head -1
echo "$CURL_BIN"
