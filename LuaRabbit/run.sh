#!/usr/bin/env bash
# LuaRabbit -- Redis Lua pattern-recursion stack exhaustion (fixed in 124bc7e).
set -u
cd "$(dirname "$0")"

VULN_SHA=63cf48ce4ef9f739abc230c5aaef3a726f62036a   # parent of the fix (vulnerable)
FIX_SHA=124bc7ef45e2baa63afbec3a956fb6c41358c450    # deps/lua: add match() depth limit

TC=/home/millie/tools/toolchain/x86_64-linux-musl-cross/bin
if [ -x "$TC/x86_64-linux-musl-gcc" ]; then
  export PATH="$TC:$PATH"; CCBIN=x86_64-linux-musl-gcc; EXTRA=-static
else
  CCBIN=gcc; EXTRA=""
fi

mkdir -p bin build
for pair in "vuln:$VULN_SHA" "fixed:$FIX_SHA"; do
  name=${pair%%:*}; sha=${pair#*:}
  [ -x "bin/redis-server-$name" ] && continue
  echo "== fetching redis $name ($sha) =="
  timeout 120 curl -sL -o "build/$name.tar.gz" \
    "https://codeload.github.com/redis/redis/tar.gz/$sha" || exit 1
  mkdir -p "build/$name"
  tar -xzf "build/$name.tar.gz" -C "build/$name" --strip-components=1 || exit 1
  echo "== building $name (real redis source) =="
  if ! timeout 500 make -C "build/$name/src" -j"$(nproc)" redis-server \
        MALLOC=libc CC="$CCBIN" LDFLAGS="$EXTRA" >"build/$name.log" 2>&1; then
    tail -20 "build/$name.log"; exit 1
  fi
  cp "build/$name/src/redis-server" "bin/redis-server-$name" || exit 1
done

timeout 120 python3 poc.py bin/redis-server-vuln bin/redis-server-fixed | tee /tmp/luarabbit.out
rc=${PIPESTATUS[0]}
if grep -q 'LUARABBIT-CONFIRMED' /tmp/luarabbit.out; then exit 0; fi
exit "$rc"
