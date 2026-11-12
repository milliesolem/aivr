# QemuOverrun — QEMU VHDX BAT out-of-bounds read (CWE-125, CWE-190) → host crash

A malicious VHDX disk image whose `Virtual Disk Size` metadata is oversized
(> 4 PiB) makes QEMU's `block/vhdx.c` truncate the BAT-entry count to a `uint32_t`,
undersizing the block-allocation table. `vhdx_block_translate()` then indexes that
BAT with no bounds check, so a read or write at a high-but-in-range offset
dereferences `s->bat[bat_idx]` far past the allocation — a heap out-of-bounds
**read** that crashes the QEMU process (SIGSEGV). The real `qemu-img`/`qemu-io`
binary dies with SIGSEGV.

| Product + version            | CVSS 3.1                                  | CWE                    |
|------------------------------|-------------------------------------------|------------------------|
| QEMU ≤ 11.1.3 (stable-11.1; Debian 10.0.13)| **5.5 MEDIUM** — `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` | CWE-125 (OOB read), CWE-190 (int wrap → CWE-131 undersized buffer) |

## Fix commit

`67198583a1ef3432c784f2802c5cda914bc14ca8` — *"block/vhdx: Prevent out-of-bounds BAT
accesses with malicious vhdx files"* (Thomas Huth, 2026-10-23, merged 2026-11-09).
Present in master and `v11.2.0-rc0`; **not** backported to `stable-11.1` (last
`block/vhdx.c` change there was 2025-09-15), so the stable line is still vulnerable.

## Vulnerable code (pre-fix)

```c
/* vhdx_parse_metadata(): virtual_disk_size read straight from the image,
 * with NO bound to VHDX_MAX_IMAGE_SIZE (64 TiB). */
s->virtual_disk_size = le64_to_cpu(s->virtual_disk_size);

/* vhdx_calc_bat_entries(): block count computed into a uint32_t. */
uint32_t data_blocks_cnt, bitmap_blocks_cnt;
data_blocks_cnt = DIV_ROUND_UP(s->virtual_disk_size, s->block_size);   // wraps
...
s->bat_entries = data_blocks_cnt + ((data_blocks_cnt - 1) >> s->chunk_ratio_bits);

/* vhdx_block_translate(): sector -> BAT index, then dereference with no check. */
sinfo->bat_idx = sector_num >> s->sectors_per_block_bits;
sinfo->bat_idx += sinfo->bat_idx >> s->chunk_ratio_bits;
...
sinfo->file_offset = s->bat[sinfo->bat_idx] & VHDX_BAT_FILE_OFF_MASK;  // OOB read
```

The fix adds `if (s->virtual_disk_size > VHDX_MAX_IMAGE_SIZE) { ret = -EFBIG; }` at the
metadata parse and `assert(sinfo->bat_idx < s->bat_entries)` before the dereference.

## Exploit chain

1. **Craft** a valid VHDX, then patch the `Virtual Disk Size` metadata item to
   `2^55 + 2^23` bytes (32 PiB + 8 MiB). With `block_size` = 8 MiB this makes
   `data_blocks_cnt = DIV_ROUND_UP(2^55+2^23, 2^23) = 2^32 + 1`, which truncates to
   **1** in a `uint32_t`, so `bat_entries = 1`.
2. **Open** — `vhdx_parse_metadata` accepts the huge size (no 64 TiB bound);
   `bs->total_sectors ≈ 2^46`, so every sector up to ~2^46 is "in range".
3. **Trigger** — a read/write at offset ≥ 1 TiB (sector ≥ 2^31) yields
   `bat_idx ≥ 2^17`; `s->bat[bat_idx]` reads 8 bytes ~1 GiB past the ~1 MiB BAT
   heap allocation → SIGSEGV. The masked read result (`& VHDX_BAT_FILE_OFF_MASK`)
   becomes a file offset into the attacker's own image, so no host memory is
   disclosed. On the write path, `vhdx_co_writev` calls `vhdx_block_translate`
   (the OOB **read**) *before* `vhdx_update_bat_table_entry` (the write), so the
   out-of-bounds **write** is never reached — both crash sites are the OOB read.
   Impact = host/VM crash (DoS).

## Run

```bash
cd poc/QemuOverrun && bash run.sh
```

Expected: `qemu-img info` reports `virtual size: 32 PiB`; the unpatched 1 MiB control
image errors cleanly at the 1 PiB offset; the patched image SIGSEGVs (exit 139) on
both read and write; the script prints `QEMUOVERRUN-OK`.

## Exploitability assessment (honest)

- **Preconditions.** Attacker supplies a VHDX image; a QEMU host opens it via
  `qemu-img info/convert/check/map`, `qemu-io`, `qemu-storage-daemon`, or as a VM
  disk. No privilege on the host is needed to supply the image (cloud image-import
  pipelines and shared VM images are the classic vectors). The trigger requires I/O
  at a high offset, trivially reachable by a guest on a >4 PiB virtual disk or via
  `qemu-io`/`qemu-img dd`.
- **Demonstrated.** Real `qemu-io` SIGSEGV on both read and write paths — a
  deterministic out-of-bounds **read** that crashes the process (DoS). The masked
  read result is a file offset into the attacker's own image (no host-memory
  disclosure), and the write-path OOB store is unreachable (the read crashes first).
- **Not demonstrated / corrected.** Full RCE or an out-of-bounds *write* primitive.
  An earlier draft claimed a heap OOB write (`s->bat[bat_idx] |= state`); the critic
  pass verified that `vhdx_co_writev` calls `vhdx_block_translate` (the OOB read)
  before `vhdx_update_bat_table_entry` (the write), so the write is never reached
  past the allocation. Severity is therefore DoS-only, matching Palo Alto Networks'
  independent 5.5 MEDIUM assessment of the same bug.

## Self-critique (3 ways this might NOT fire, and how each was checked)

1. **Maybe the generic block layer clamps the I/O before `vhdx_co_readv`.** Checked:
   `bs->total_sectors` is set from the full 64-bit `virtual_disk_size`, so the 1 PiB
   offset is *in range*; `qemu-img map` and `qemu-img info` both report the full
   32 PiB extent. The offset reaches `vhdx_block_translate` (the segfault proves it).
2. **Maybe `vhdx_check_bat_entries` rejects the image at open.** Checked: it only
   iterates `i < bat_entries` (== 1 after truncation) and validates that single
   entry, so it cannot see the OOB index; `qemu-img info` opens the image cleanly.
3. **Maybe the OOB read lands in mapped heap and doesn't crash.** This is why the
   offset was chosen so `bat_idx = 2^27` — 8 bytes at ~1 GiB past a ~1 MiB allocation,
   which is reliably unmapped. A smaller `bat_idx` (e.g. `bat_entries`+1) would be a
   silent over-read within the allocation, but even then the result is masked to a
   file offset (`& VHDX_BAT_FILE_OFF_MASK`) and never returned to the attacker — so
   there is no information-disclosure variant, only the crash.

## Battery rule (class: int-overflow-alloc)

```json
{
  "id": "int-overflow-alloc",
  "pcre2": "(?s)uint32_t\\s+\\w+\\s*=\\s*DIV_ROUND_UP\\([^;]*virtual_disk_size[^;]*;",
  "triage_note": "size/block-count computed into a type too narrow for the source field; confirm the source is attacker-controlled (image/network metadata) and the resulting count indexes an allocation without a later bounds check.",
  "examples": [
    "uint32_t data_blocks_cnt = DIV_ROUND_UP(s->virtual_disk_size, s->block_size); // block/vhdx.c:884",
    "uint32_t data_blocks_cnt, bitmap_blocks_cnt; data_blocks_cnt = DIV_ROUND_UP(s->virtual_disk_size, s->block_size);"
  ],
  "noise_tier": "low"
}
```
