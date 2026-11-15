#!/usr/bin/env bash
# Rebuild ffmpeg-vuln and ffmpeg-fixed from upstream FFmpeg n9.0.2 source.
# Requires: git, python3, network (to clone), and a C compiler. Defaults to the
# musl-gcc cross toolchain shipped with this environment; set CC to override.
set -euo pipefail
cd "$(dirname "$0")"

MUSL=/home/millie/tools/toolchain/x86_64-linux-musl-cross/bin
CC="${CC:-$MUSL/x86_64-linux-musl-gcc}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/FFmpeg"

echo "[+] cloning FFmpeg n9.0.2 (vulnerable release)"
git clone --quiet --depth 1 --branch n9.0.2 https://github.com/FFmpeg/FFmpeg.git "$SRC"

echo "[+] instrumenting av_malloc with a canary redzone (ASAN unavailable)"
python3 - "$SRC/libavutil/mem.c" <<'PYEOF'
import sys
path = sys.argv[1]
src = open(path).read()

helpers = r'''/* AIVR PoC: canary-redzone allocator instrumentation (ASAN substitute). */
#include <stdio.h>
#define AIVR_CANARY_HDR_SIZE 64
#define AIVR_CANARY_REDZONE 1024
#define AIVR_CANARY_MAGIC 0x414956525a4f4e45ULL
#define AIVR_CANARY_BYTE 0xA5
typedef struct AivrCanaryHdr { uint64_t magic; size_t size; uint64_t _pad[6]; } AivrCanaryHdr;
static void aivr_canary_init(void *base, size_t size) {
    AivrCanaryHdr *h = (AivrCanaryHdr *)base;
    h->magic = AIVR_CANARY_MAGIC; h->size = size;
    memset((uint8_t *)base + AIVR_CANARY_HDR_SIZE + size, AIVR_CANARY_BYTE, AIVR_CANARY_REDZONE);
}
static void aivr_canary_verify(void *base) {
    const AivrCanaryHdr *h = (const AivrCanaryHdr *)base;
    const uint8_t *rz;
    if (h->magic != AIVR_CANARY_MAGIC) return;
    rz = (const uint8_t *)base + AIVR_CANARY_HDR_SIZE + h->size;
    for (size_t i = 0; i < AIVR_CANARY_REDZONE; i++)
        if (rz[i] != AIVR_CANARY_BYTE) {
            fprintf(stderr, "AIVR-CANARY: HEAP-BUFFER-OVERFLOW detected in av_malloc buffer (size=%zu bytes): redzone byte %zu == 0x%02x (expected 0x%02x)\n", h->size, i, rz[i], AIVR_CANARY_BYTE);
            fflush(stderr); abort();
        }
}
'''
def rep(old, new):
    global src
    assert old in src, "patch target not found: " + old[:60]
    src = src.replace(old, new, 1)

rep("void *av_malloc(size_t size)\n{", helpers + "void *av_malloc(size_t size)\n{")

rep('''{
    void *ptr = NULL;

    if (size > atomic_load_explicit(&max_alloc_size, memory_order_relaxed))
        return NULL;

#if HAVE_POSIX_MEMALIGN
    if (size) //OS X on SDK 10.6 has a broken posix_memalign implementation
    if (posix_memalign(&ptr, ALIGN, size))
        ptr = NULL;
#elif HAVE_ALIGNED_MALLOC
    ptr = _aligned_malloc(size, ALIGN);
#elif HAVE_MEMALIGN
#ifndef __DJGPP__
    ptr = memalign(ALIGN, size);
#else
    ptr = memalign(size, ALIGN);
#endif
''', '''{
    void *base = NULL;
    void *ptr = NULL;
    size_t total;

    if (size > atomic_load_explicit(&max_alloc_size, memory_order_relaxed))
        return NULL;

    total = AIVR_CANARY_HDR_SIZE + size + AIVR_CANARY_REDZONE;
#if HAVE_POSIX_MEMALIGN
    if (size) //OS X on SDK 10.6 has a broken posix_memalign implementation
    if (posix_memalign(&base, ALIGN, total))
        base = NULL;
#elif HAVE_ALIGNED_MALLOC
    base = _aligned_malloc(total, ALIGN);
#elif HAVE_MEMALIGN
#ifndef __DJGPP__
    base = memalign(ALIGN, total);
#else
    base = memalign(total, ALIGN);
#endif
''')

rep('''#else
    ptr = malloc(size);
#endif
    if(!ptr && !size) {
        size = 1;
        ptr= av_malloc(1);
    }
#if CONFIG_MEMORY_POISONING
    if (ptr)
        memset(ptr, FF_MEMORY_POISON, size);
#endif
    return ptr;
}
''', '''#else
    base = malloc(total);
#endif
    if(!base && !size) {
        size = 1;
        base = av_malloc(1);
    }
    if (base) {
        aivr_canary_init(base, size);
        ptr = (uint8_t *)base + AIVR_CANARY_HDR_SIZE;
#if CONFIG_MEMORY_POISONING
        memset(ptr, FF_MEMORY_POISON, size);
#endif
    }
    return ptr;
}
''')

rep('''void av_free(void *ptr)
{
#if HAVE_ALIGNED_MALLOC
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}
''', '''void av_free(void *ptr)
{
    if (!ptr)
        return;
    aivr_canary_verify((uint8_t *)ptr - AIVR_CANARY_HDR_SIZE);
#if HAVE_ALIGNED_MALLOC
    _aligned_free((uint8_t *)ptr - AIVR_CANARY_HDR_SIZE);
#else
    free((uint8_t *)ptr - AIVR_CANARY_HDR_SIZE);
#endif
}
''')
open(path, "w").write(src)
print("[+] mem.c instrumented")
PYEOF

echo "[+] building vulnerable binary (unmodified n9.0.2)"
(
  cd "$SRC"
  ./configure --cc="$CC" --ld="$CC" --extra-cflags="-O0 -g" --extra-ldflags="-static" \
    --host-cc="$CC" --host-ldflags="-static" --pkg-config=false \
    --disable-everything --enable-ffmpeg --disable-doc --disable-network --disable-autodetect \
    --disable-x86asm --disable-inline-asm \
    --enable-avutil --enable-avfilter --enable-avcodec --enable-avformat --enable-swresample --enable-swscale \
    --enable-filter=anlmdn,aresample,aformat --enable-protocol=file \
    --enable-demuxer=wav --enable-muxer=wav \
    --enable-decoder=pcm_s16le,pcm_s16be,pcm_s32le,pcm_f32le --enable-encoder=pcm_s16le >/dev/null
  rm -f ffbuild/bin2c ffbuild/bin2c_host.o
  make -j"$(nproc)" ffmpeg >/dev/null
)
cp "$SRC/ffmpeg" "$(dirname "$0")/ffmpeg-vuln"
echo "[+] ffmpeg-vuln built"

echo "[+] applying the one-line fix and rebuilding ffmpeg-fixed"
sed -i 's/for (int i = S; i < H + S; i++) {/for (int i = S; i < in->nb_samples + S; i++) {/' "$SRC/libavfilter/af_anlmdn.c"
(
  cd "$SRC"
  make -j"$(nproc)" ffmpeg >/dev/null
)
cp "$SRC/ffmpeg" "$(dirname "$0")/ffmpeg-fixed"
echo "[+] ffmpeg-fixed built"

echo "[+] done. Re-run: bash run.sh"
