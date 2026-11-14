# DolphiOverrun — Dolphin emulator legacy-savestate LZO decompression heap OOB write (CWE-787)

| | |
|---|---|
| **Product / version** | Dolphin Emulator (`dolphin-emu/dolphin`) — all releases up to and including **2609a** (2026-10-07); fixed in **2609b** (2026-11-07) |
| **CVSS** | `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` = **7.8 High** |
| **CWE** | **CWE-787** Out-of-bounds Write (heap) + **CWE-120** classic buffer overflow (global) |

## What it is

`GetVersionFromLZO()` in `Source/Core/Core/State.cpp` parses the compressed version
block of a **legacy** savestate (`.sav`). Two attacker-controlled fields from the
24-byte file header are trusted without validation, producing two independent
out-of-bounds writes when a crafted `.sav` is loaded:

1. **Heap overrun (primary).** The decompression *output* buffer is sized from
   `header.legacy_header.lzo_size` (a `u32` at offset 8 of the file, fully
   attacker-controlled), and the **unsafe** `lzo1x_decompress()` API — which takes
   no output-capacity argument — is used to fill it. A block that decompresses to
   more than `lzo_size` bytes writes straight past the heap allocation.
2. **Global overrun.** The compressed *input* length `cur_len` (the `u32` read
   immediately after the header) is copied into a fixed `static unsigned char
   out[OUT_LEN]` (139331 bytes) staging buffer with **no `cur_len <= OUT_LEN` check**,
   so an oversized block overruns that buffer too.

The fix (commit `f662e858`, PR #14968, "Core: Bound legacy savestate LZO
decompression") closes both: it uses the fixed legacy block size `IN_LEN` as the
output capacity (ignoring `lzo_size`), rejects `cur_len > OUT_LEN` before reading,
and switches to the bounds-checking `lzo1x_decompress_safe()`.

- Fix commit: https://github.com/dolphin-emu/dolphin/commit/f662e8585f327e03da026f58bc1e7cebb159b8cb
- Vulnerable code (`96f81812`, the fix's parent):
  https://github.com/dolphin-emu/dolphin/blob/96f8181230e6b4445675e7b6c5d913c189f4d7bb/Source/Core/Core/State.cpp#L510-L520

## Vulnerable code (pre-fix, `State.cpp:510-520`)

```c
static bool GetVersionFromLZO(StateHeader& header, File::IOFile& f)
{
  lzo_uint32 cur_len = 0;  // size of compressed bytes
  lzo_uint new_len = 0;    // size of uncompressed bytes
  Common::UniqueBuffer<u8> buffer(header.legacy_header.lzo_size);   // <-- attacker size

  if (!f.ReadArray(&cur_len, 1) || !f.ReadBytes(out, cur_len))       // <-- no cur_len<=OUT_LEN
    return false;

  const int res = lzo1x_decompress(out, cur_len, buffer.data(), &new_len, nullptr); // <-- UNSAFE
  ...
}
```

The fixed version replaces the last line with
`lzo1x_decompress_safe(out, cur_len, buffer.data(), &new_len, nullptr)` after
allocating `buffer` as `IN_LEN` bytes and rejecting `cur_len > OUT_LEN`.

## Exploit chain

1. Craft a 24-byte `StateHeaderLegacy` with `lzo_size = 64` (offset 8), then a
   `u32 cur_len`, then an LZO block that decompresses to 4096 bytes.
2. `ReadStateHeaderFromFile()` sees `lzo_size != 0` and calls `GetVersionFromLZO()`.
3. The unsafe `lzo1x_decompress()` writes 4096 bytes into the 64-byte heap buffer —
   **4032 bytes past the allocation**.
4. A second crafted file with `cur_len = OUT_LEN + 128` overruns the global
   `out[OUT_LEN]` staging buffer by 128 bytes at the `ReadBytes` step.

## Exploitability assessment (honest preconditions + threat model)

- **Threat model.** Loading a savestate is a routine, attacker-reachable user action:
  `.sav` files are freely shared and downloaded (forums, save databases, "100% save"
  packs, NetPlay). The entire header — including `lzo_size` and `cur_len` — is
  attacker-controlled; there is no signature or validation. No privileges are needed.
- **Impact.** Two deterministic OOB writes. The overrun *length* and the *decompressed
  bytes* are attacker-influenced (LZO is a real compression format, so the attacker
  controls the decompressed payload). This is a textbook heap-corruption primitive:
  the deterministic floor is a crash/DoS of the emulator, and the realistic ceiling —
  with ASLR/guard-page mitigation in play — is arbitrary code execution in the host
  process. This is the same severity class as Dolphin's own earlier advisories (GCZ
  heap overflow `GHSA-7pvc-j9pm-c2rp`, the 2606a NetPlay LZO overflow, and the 2609a
  save-state OOB write), which Dolphin treats as security vulnerabilities.
- **Fix status.** Fixed in the 2609b hotfix (2026-11-07): the source at tag
  `2609b` uses `lzo1x_decompress_safe` + a fixed `IN_LEN` output buffer + a
  `cur_len > OUT_LEN` reject. Every earlier release — 2609a (2026-10-07) and all
  prior — still ships the unsafe `lzo1x_decompress` into an `lzo_size`-sized buffer
  with no input bound. **No CVE or GHSA is assigned** to this specific bug (Dolphin's
  only public advisory in this window is the unrelated GCMemcardDirectory issue), so
  it has gone un-tracked by the security ecosystem despite being a real heap overflow.

## Run instructions

```bash
bash run.sh
```

Requires the `zig` compiler (bundled at `/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig`;
override with `ZIG=/path/to/zig`). The harness compiles the **real** Dolphin-vendored
`minilzo.c` (under `vendor/`, byte-identical to `Externals/LZO/minilzo.c`) and drives it
through a faithful reproduction of the vulnerable and fixed `GetVersionFromLZO()`.

Expected output ends with:

```
[vuln ] lzo1x_decompress   res=0  wrote=4096 bytes  (buffer=64 bytes)  canary-clobbered=4032
        HEAP-OVERRUN: decompressor wrote past the lzo_size buffer
[fixed] lzo1x_decompress_safe res=0  wrote=4096 bytes  (buffer=131072 bytes)  canary-clobbered=0
        CONTAINED: no write past the fixed IN_LEN buffer
[vuln ] ReadBytes(out, cur_len=139459) into out[139331]  canary-clobbered=128
        INPUT-OVERRUN: read past the fixed staging buffer
[fixed] cur_len > OUT_LEN -> rejected before reading (no overrun)
        CONTAINED: oversized block rejected
DOLPHIOVERRUN-OK
```

## Self-critique — three ways this trigger might NOT work, and how each was checked

1. **"The path is dead / legacy-only."** `ReadStateHeaderFromFile()` (State.cpp:580)
   calls `GetVersionFromLZO()` whenever `lzo_size != 0`, and `lzo_size` is read
   straight from the file at offset 8 — so any crafted `.sav` reaches the sink. The
   "legacy" label refers to the *format*, not dead code; the branch is live in every
   current build. *Checked against `State.cpp:574-586` at `96f81812`.*
2. **"`ReadBytes`/`UniqueBuffer` bounds-check internally."** They do not.
   `File::IOFile::ReadBytes` writes exactly the requested length into the caller's
   pointer with no knowledge of its size, and `UniqueBuffer<u8>(n)` allocates exactly
   `n` bytes. `lzo1x_decompress` (unlike `_safe`) takes no capacity. *Checked against
   the minilzo API in `vendor/minilzo.h` (the `_safe` variant is what the fix uses).*
3. **"The decompressed output can't exceed a small `lzo_size`."** It trivially can:
   LZO achieves high ratios on repeated data, so a ~110-byte compressed block expands
   to 4096 bytes (demonstrated live in the harness). The attacker fully controls the
   compression ratio. *Checked by running the harness, which reports
   `comp_len≈110 → new_len=4096`.*
