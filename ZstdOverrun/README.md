# ZstdOverrun — out-of-bounds write in zstd's recursive block splitter

An out-of-bounds array **write** (CWE-787) in [facebook/zstd](https://github.com/facebook/zstd)'s
compression path. The recursive block splitter writes split positions into a
fixed 196-entry array and only checks its budget on function entry, so a
left-child recursion can fill the array before its ancestors write their own
split positions — overwriting the adjacent compression-context field
(`ZSTD_entropyCTablesMetadata_t entropyMetadata`) that sits right after the array.

| | |
|---|---|
| **Product / version** | libzstd ≤ 1.5.7 (latest release, 2025-02-18); `lib/compress/zstd_compress.c` |
| **CVSS** | 3.3 LOW — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` |
| **CWE** | CWE-787 Out-of-bounds Write |

## The vulnerability

`ZSTD_deriveBlockSplitsHelper()` (lib/compress/zstd_compress.c) writes intra-block
split indices into `ZSTD_blockSplitCtx.partitions[]`:

```c
/* lib/compress/zstd_compress_internal.h — the undersized array */
#define ZSTD_MAX_NB_BLOCK_SPLITS 196
typedef struct {
    ...
    U32 partitions[ZSTD_MAX_NB_BLOCK_SPLITS];   /* 196 entries */
    ZSTD_entropyCTablesMetadata_t entropyMetadata;  /* <- gets overwritten */
} ZSTD_blockSplitCtx;

/* lib/compress/zstd_compress.c:4197 (v1.5.7) */
static void ZSTD_deriveBlockSplitsHelper(seqStoreSplits* splits, size_t startIdx,
                                         size_t endIdx, ZSTD_CCtx* zc,
                                         const SeqStore_t* origSeqStore) {
    ...
    /* budget checked ONLY on function entry (line 4210) */
    if (endIdx - startIdx < MIN_SEQUENCES_BLOCK_SPLITTING ||
        splits->idx >= ZSTD_MAX_NB_BLOCK_SPLITS) {
        return;
    }
    ...
    if (estimatedFirstHalfSize + estimatedSecondHalfSize < estimatedOriginalSize) {
        ZSTD_deriveBlockSplitsHelper(splits, startIdx, midIdx, zc, origSeqStore); /* left */
        splits->splitLocations[splits->idx] = (U32)midIdx;   /* line 4228 — OOB when idx == 196 */
        splits->idx++;
        ZSTD_deriveBlockSplitsHelper(splits, midIdx, endIdx, zc, origSeqStore);   /* right */
    }
}
```

The left-child recursion can push `splits->idx` to 196. When the recursion
returns, the parent writes `splitLocations[196]` — one past the array — and the
terminator write in `ZSTD_deriveBlockSplits()` (`splitLocations[splits.idx] = nbSeq`)
lands further out of bounds.

## The fix (unreleased)

Upstream commit [`974238ca`](https://github.com/facebook/zstd/commit/974238ca9e5e05fc0241aa09e10b4837d77cf78e)
("Fix block splitter partition bounds", 2026-11-10) re-checks the budget after
the left recursion, reserves one extra partition slot, and asserts the final count:

```c
        ZSTD_deriveBlockSplitsHelper(splits, startIdx, midIdx, zc, origSeqStore);
        if (splits->idx >= ZSTD_MAX_NB_BLOCK_SPLITS)   /* NEW: re-check after left recursion */
            return;
        splits->splitLocations[splits->idx] = (U32)midIdx;
        splits->idx++;
        ZSTD_deriveBlockSplitsHelper(splits, midIdx, endIdx, zc, origSeqStore);
```

```c
-   U32 partitions[ZSTD_MAX_NB_BLOCK_SPLITS];
+   U32 partitions[ZSTD_MAX_NB_BLOCK_SPLITS + 1]; /* splits, followed by the end of the block */
```

It is **not in any release** — the latest release v1.5.7 dates to 2025-02-18.

## Exploit chain

1. The application compresses data through the block-level **external sequence
   producer** API (`ZSTD_registerSequenceProducer()` + `ZSTD_compress2()`), with
   `ZSTD_c_splitAfterSequences` enabled and `ZSTD_c_validateSequences == 1`.
   This is the offload / hardware-accelerated / custom sequence-generator path
   (see `contrib/externalSequenceProducer`); the CLI and the default
   `ZSTD_compress()` path do **not** use it.
2. The attacker's data is parsed into a sequence stream. A 128,000-byte input of
   **38,400 valid 3-byte matches** makes the recursive splitter perform more than
   196 dyadic splits.
3. `ZSTD_deriveBlockSplitsHelper()` writes past `partitions[196]` into the
   adjacent `ZSTD_entropyCTablesMetadata_t entropyMetadata` — silent corruption
   of the compression context (CWE-787).

## Exploitability assessment

- **Real memory-safety bug, verifiable**: the differential PoC below shows four
  32-bit words written past the array (the `midIdx` split positions `0x7788`,
  `0x79e0`, `0x8340` and the `nbSeq` terminator `0x9600 == 38400`).
- **Honest scope**: the write is bounded (4 words) and its values are split
  indices, not arbitrary attacker bytes, so this is memory corruption / a
  potential crash rather than a demonstrated RCE. The corrupted field is the
  compression context's entropy-table metadata; the round-trip still succeeds,
  so the corruption is *silent*.
- **Reachability**: requires the external-sequence API (or the block-splitter
  mode) to be processing attacker-influenced data. The default
  `ZSTD_compress()` / decompression paths are **not** affected. The write stays
  within the (heap-allocated) `ZSTD_CCtx` struct — it corrupts the adjacent
  `entropyMetadata` field, not arbitrary heap — and no crash, RCE, or
  information leak is demonstrated, so the severity is LOW.

## Run

```sh
bash run.sh
```

Both binaries are the **real libzstd** compiled from upstream source with
`musl-gcc`; the only change is an 8-word canary field placed immediately after
`partitions[]` in `ZSTD_blockSplitCtx` so the out-of-bounds write is detected
deterministically (ASAN is unavailable):

- `zstd-vuln`  = tag v1.5.7 (latest release) — vulnerable.
- `zstd-fixed` = commit 974238ca — fixed.

Expected output (abridged):

```
=== [1/2] VULNERABLE — zstd v1.5.7 (latest release) ===
  canary[0] = 0x00007788 (was 0xa5a5a5a5)
  canary[1] = 0x000079e0 (was 0xa5a5a5a5)
  canary[2] = 0x00008340 (was 0xa5a5a5a5)
  canary[3] = 0x00009600 (was 0xa5a5a5a5)
compressed 128000 -> 41454 bytes
ZSTDOVERRUN-CANARY-CLOBBERED: the block splitter wrote past partitions[196] ...

=== [2/2] FIXED — zstd commit 974238ca (unreleased) ===
compressed 128000 -> 41661 bytes
ZSTDOVERRUN-CANARY-INTACT: no out-of-bounds write

RESULT: ZstdOverrun CONFIRMED
```

To rebuild the binaries from source, run `bash build.sh` (uses the local
`x86_64-linux-musl-cross` toolchain and a local zstd checkout).
