# DeltaOverrun — google/leveldb `DecodeEntry` integer overflow → OOB read

| | |
|---|---|
| **Project** | LevelDB (`google/leveldb`) — embedded key-value store |
| **Component** | `table/block.cc` — `DecodeEntry()` / `Block::Iter::ParseNextKey()` |
| **Class** | CWE-190 (integer overflow) → CWE-125 (out-of-bounds read) |
| **CVSS 3.1** | 8.1 High — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H` |
| **Affected** | 1.23 (2021-02-23) and earlier — incl. current master before the fix |
| **Fixed** | master @ [`29465588d3`](https://github.com/google/leveldb/commit/29465588d3dfdc80fba5e198037582b8fdb5dd60) (2026-11-12, **unreleased**) |

## Root cause

`DecodeEntry()` validates that a block entry's key-suffix (`non_shared`) and
value (`value_length`) fit in the remaining buffer with a single 32-bit sum:

```c
if (static_cast<uint32_t>(limit - p) < (*non_shared + *value_length)) {
    return nullptr;                       // bounds check
}
return p;
```

`*non_shared` and `*value_length` are `uint32_t`; their sum is computed in
32-bit arithmetic. A corrupt entry can set `value_length = 0xffffffff` with
`non_shared = 1`, so the sum wraps to `0` and `remaining < 0` is never true —
the bounds check is **bypassed**. `Block::Iter::ParseNextKey()` then builds the
value directly from the attacker-controlled length:

```c
value_ = Slice(p + non_shared, value_length);   // size = 0xffffffff
```

Consuming the value (`ToString()`, `compare()`, copy) reads `value_length`
bytes — up to **4 GiB past the block** — an out-of-bounds read.

The fix splits the check so the addition cannot wrap:

```c
if (static_cast<uint32_t>(limit - p) < *non_shared ||
    static_cast<uint32_t>(limit - p) - *non_shared < *value_length) {
    return nullptr;
}
```

## Exploit chain

1. An attacker crafts an SSTable block entry with `shared=0`, `non_shared=1`,
   `value_length=0xffffffff`, followed by a single key byte (the exact bytes of
   the upstream regression test `CorruptedBlockEntryLengthOverflow`).
2. A LevelDB-backed application opens the file and reads the key. `DecodeEntry`
   accepts the entry (the wrapped sum `1 + 0xffffffff == 0` defeats the check).
3. The iterator returns a value `Slice` of size `0xffffffff` with ~0 bytes of
   real data; consuming it reads up to 4 GiB out of bounds (heap disclosure /
   crash).

## Demonstration

`exploit.cc` reproduces the vulnerable and fixed `DecodeEntry` verbatim (with
the real `GetVarint32Ptr` and `Slice`), compiles with `zig c++`, and runs both
against the same corrupt block:

```
[vulnerable] DecodeEntry returned NON-NULL (bounds check bypassed)
             -> value Slice size = 4294967295 (0xffffffff), actual data remaining = 0 byte(s)
             -> value spans 0xffffffff bytes past the 16-byte block = a 4.0 GiB out-of-bounds read
[fixed]      DecodeEntry returned nullptr (corruption detected)
RESULT: INTEGER OVERFLOW -> OOB READ CONFIRMED
```

A second stage allocates the block in a heap buffer with a canary and shows the
vulnerable value `Slice` starts at the end of the block data (in the restart
array) and its `end()` lies ~4 GiB past the allocation.

## Exploitability assessment

- **Threat model:** a malicious LevelDB file (`*.ldb`/`*.sst`) — a downloaded
  cache, a synced profile, a game save, a shared directory — opened by a victim
  application. LevelDB is embedded in Chrome, Bitcoin Core, and many other
  projects, so the file often crosses a trust boundary. (`UI:R`.)
- **Preconditions:** (1) attacker can influence the block bytes of a database
  the victim opens; (2) the application reads/consumes the corrupted key's value.
- **Impact:** out-of-bounds read of up to 4 GiB past the block → heap memory
  disclosure and/or crash. No write primitive (integer overflow here does not
  directly grant `C:H`-style code execution on its own).
- **Honest note:** this is an OOB *read*, not a write; it requires a malicious
  file rather than a bare network request. Severity is bounded by that threat
  model (8.1 High), consistent with how the analogous libevent off-by-one
  (CVE-2026-63387) was rated.

## Running

```bash
bash run.sh        # compiles with zig c++ and runs
```

Expected output ends with `RESULT: INTEGER OVERFLOW -> OOB READ CONFIRMED` and
`PASS`.
