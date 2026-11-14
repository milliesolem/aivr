# LeveldbOverrun — leveldb data-block iterator integer-overflow → out-of-bounds read

A CVE-less memory-safety bug in Google's **LevelDB** (C++), still unpatched in every
released version. `table/block.cc`'s `DecodeEntry` validates a data-block entry's
size with `non_shared + value_length` — a `uint32_t` sum that **overflows**. A
crafted SSTable data block (16 bytes) defeats the bounds check and makes
`Block::Iter` hand back a *Valid* entry whose `value()` `Slice` is
**0xffffffff bytes long** starting 8 bytes into a 16-byte buffer. Any consumer of
the iterator reads out of bounds — a deterministic crash, and in heap-backed
embeddings an attacker-sized (up to 4 GiB) heap read of adjacent keys/values/blocks.

The fix (`29465588`, 2026-11-04) is **only on master** — no release ships it (1.23
from 2021-02 is still the newest tag), so every released leveldb is affected.

| | |
|---|---|
| **Product / version** | Google LevelDB **1.23** (latest release) and all earlier releases; `master` before `29465588` |
| **CVSS / severity** | 5.5 Medium — `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H` (demonstrated crash/DoS; the attacker-controlled-length OOB read is a plausible but un-demonstrated bounded info-disclosure, `C:L` ≈ 6.1 if credited) |
| **CWE** | CWE-190 (integer overflow) → CWE-125 (out-of-bounds read) |
| **Fix commit** | `29465588d3dfdc80fba5e198037582b8fdb5dd60` (unreleased, master only) |
| **Vulnerable code** | `table/block.cc:71` `if (static_cast<uint32_t>(limit - p) < (*non_shared + *value_length))` — the `uint32_t` sum wraps |
| **Critical op** | `table/block.cc:270` `value_ = Slice(p + non_shared, value_length);` — the OOB `Slice` of length `0xffffffff` |

## Vulnerability

`DecodeEntry` reads `shared`, `non_shared`, `value_length` as varints from the block
and checks the entry fits with a single comparison on `non_shared + value_length`.
Because both operands are `uint32_t`, the addition wraps. A block that encodes
`non_shared = 1`, `value_length = 0xffffffff` sums to `0`, so `limit - p < 0` is
false and the entry passes. `ParseNextKey` then does:

```cpp
key_.append(p, non_shared);                 // 1 byte, in bounds
value_ = Slice(p + non_shared, value_length); // Slice(block+8, 0xffffffff)  <-- OOB
```

`NextEntryOffset()` wraps too, so `current_ < restarts_` and the iterator reports
`Valid()`. The caller receives a value `Slice` that extends ~4 GiB past the block.

## Exploit chain

1. Craft a 16-byte block: `varint(0)` `varint(1)` `varint(0xffffffff)` `'a'` +
   `restart[0]=0` `num_restarts=1` (byte-for-byte the regression test leveldb later added).
2. Open it with the real `Block::NewIterator(BytewiseComparator())` and `SeekToFirst()`.
3. The vulnerable build returns `Valid()==true`, `value().size()==4294967295`; reading
   the value runs off the block (into a `PROT_NONE` guard page in the PoC) → `SIGSEGV`.
4. The fixed build rejects the identical block with `Status::Corruption` before any read.

## Honest threat model

* **Reachability**: the input is an on-disk SSTable block, not a network socket. LevelDB's
  explicit contract is to detect corrupt blocks gracefully and return `Status::Corruption`
  (disk errors, torn writes, tampered/imported DBs). This bug breaks that contract with an
  OOB read. An attacker must supply a corrupted/crafted DB file (e.g. a shared/imported
  database, restored backup, or synced profile) that the victim then opens — `UI:R`, `PR:N`.
* **Demonstrated impact**: deterministic process crash (`SIGSEGV`) — `A:H`.
* **Not demonstrated**: the read length is fully attacker-controlled and, in heap-backed
  embeddings (leveldb's table cache), reads adjacent heap (other blocks, keys, values), so
  info disclosure (`C:H`) is a real consequence rather than something the PoC exfiltrates.
* No arbitrary write / RCE primitive; the overflow only weakens a length check, it does not
  corrupt heap metadata.
* **Prior public reports**: the same overflow was reported publicly on GitHub before the
  fix (issue #1348 "Block entry bounds check wraps around"; open fix PRs #1320/#1323/#1353/
  #1370/#1379). Google's VRP reviewed the first report as valid and routed it to a public
  issue (not embargo), and the team's own fix only landed 2026-11-04. It has **no CVE** and
  the fix is **unreleased** — so the finding is "0-day" only in the sense that no patched
  release exists, not that it is a novel/secret discovery.

## Run

```bash
cd poc/LeveldbOverrun
bash run.sh          # builds vulnerable (1.23) + fixed (29465588) with zig c++, runs both
```

Expect `LEVELDBOVERRUN-OK` and exit 0: the vulnerable build prints
`VULN: iter->Valid()==true ... value.size()=4294967295` then `SIGSEGV` (exit 139); the
fixed build prints `CORRUPTION-DETECTED` and exits 0.

Requires `zig` (set `ZIG=/path/to/zig`; default `/home/millie/tools/toolchain/zig-linux-x86_64-0.14.0/zig`).
