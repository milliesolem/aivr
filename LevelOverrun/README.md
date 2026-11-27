# LevelOverrun — Google leveldb block-decoder integer overflow → out-of-bounds read

`table/block.cc` `DecodeEntry` validates an entry's length with a bounds check
that **sums two attacker-controlled 32-bit lengths in `uint32_t`**, so the sum
can wrap and defeat the check. A crafted leveldb block (`non_shared=1`,
`value_length=0xffffffff` → sum `0`) passes the check, and the block iterator
hands back a value `Slice` of length `0xffffffff` (~4 GiB) starting at the end of
a tiny heap buffer — any read of that value is **out of bounds**.

| | |
|---|---|
| **Product** | Google **leveldb** ≤ 1.23 (latest release) and all commits before `29465588d3` (fix **unreleased**) |
| **CVSS** | 3.1: **6.1 MEDIUM** `AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H` |
| **CWE** | CWE-190 (Integer Overflow) → CWE-125 (Out-of-bounds Read) |
| **Status** | 0-day — fix merged 2026-11-04, no release contains it; leveldb 1.23 (2021) is the latest tag |

- **Fix commit:** [`29465588d3`](https://github.com/google/leveldb/commit/29465588d3dfdc80fba5e198037582b8fdb5dd60) — "Prevent potential integer overflow when validating block entry lengths."
- **Vulnerable (fix parent):** `bb74ef739973a70ca9f0d90788a1da89b788c0ad`

## Root cause (`table/block.cc`)

```cpp
// vulnerable (<= 1.23 / pre-29465588d3)
if (static_cast<uint32_t>(limit - p) < (*non_shared + *value_length)) {
  return nullptr;
}
return p;
```

`*non_shared` and `*value_length` are `uint32_t` varints read straight from the
block being decoded. `*non_shared + *value_length` is a `uint32_t` addition that
**wraps**: with `non_shared = 1`, `value_length = 0xffffffff` the sum is `0`, so
`(limit - p) < 0` is false and the overflowing entry is accepted. The caller
`Block::Iter::ParseNextKey` then does `value_ = Slice(p + non_shared,
value_length)`, i.e. a ~4 GiB slice starting at the end of the block buffer.

The fix checks the two lengths separately so no addition can overflow:

```cpp
// fixed (29465588d3)
if (static_cast<uint32_t>(limit - p) < *non_shared ||
    static_cast<uint32_t>(limit - p) - *non_shared < *value_length) {
  return nullptr;
}
```

## PoC

`poc.cc` drives the **real vendored upstream leveldb** `Block` iterator
(`leveldb/` here is copied verbatim from upstream, fixed `block.cc`). `build.sh`
compiles it twice with `zig cc`: once with the real fixed `block.cc`, and once
with the single overflow-prone check reverted to the pre-fix form. The crafted
block is exactly leveldb's own `CorruptedBlockEntryLengthOverflow` regression-test
input. The harness forks a child that walks the returned value slice to prove the
over-read is real (it faults).

```
sh run.sh
```

Observed:

```
=== VULNERABLE (leveldb <= 1.23 / pre-29465588d3) ===
[VULNERABLE] after SeekToFirst: Valid=1  status.IsCorruption=0
[VULNERABLE] iterator ACCEPTED the corrupt entry: value.size=4294967295, value end is 4294967287 bytes past the 16-byte block buffer
[VULNERABLE] reading the value slice crashed with SIGSEGV -> OUT-OF-BOUNDS READ confirmed. PWNED.

=== FIXED (leveldb 29465588d3) ===
[FIXED] after SeekToFirst: Valid=0  status.IsCorruption=1
[FIXED] DecodeEntry rejected the overflowing entry -> no OOB. BLOCKED.
```

Same harness and crafted block; only the three-line `DecodeEntry` check changes,
so the behavioural delta is attributable purely to the leveldb code under test.

## Exploitability & honest scope

- **Trigger:** an application reads a leveldb table/block the attacker controls or
  can corrupt — a malicious/corrupt `.ldb` file, an imported/synced database, a
  backup, or on-disk corruption. leveldb is embedded in widely-deployed software
  (Chromium IndexedDB/LevelDB, Bitcoin Core and other chain nodes, many
  self-hosted apps), so a hostile database file is a realistic input.
- **Demonstrated impact:** a deterministic **out-of-bounds read → crash
  (DoS, A:H)**. Because the over-read length is forced to ~4 GiB by the wrap, the
  demonstrated primitive is a crash; an information leak (C:L) is plausible where a
  consumer copies a prefix of the oversized value before the fault, but is not
  demonstrated here, hence the conservative MEDIUM rating.
- This is a genuine, unreleased-fix memory-safety 0-day in a prominent Google C++
  library (≈39.6k★). It is not remote-unauthenticated code execution — scored
  honestly as MEDIUM.

## Remediation

Pick up commit `29465588d3` (two-step length check). As of this writing no tagged
leveldb release includes the fix; vendors tracking releases (1.23) remain
vulnerable and should cherry-pick it.
