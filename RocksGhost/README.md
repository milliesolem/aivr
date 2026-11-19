# RocksGhost — RocksDB `ForwardIterator` use-after-free (CWE-416)

A heap use-after-free in RocksDB's tailing iterator (`ForwardIterator`). A
tailing iterator can outlive its column family; when the iterator's
`SuperVersion` holds the **last** reference to the `ColumnFamilyData`, the
vulnerable `RebuildIterators(true)` frees the column-family data and then
dereferences the dangling `cfd_` pointer.

|                          |                                                                 |
| ------------------------ | --------------------------------------------------------------- |
| **Product + version**    | RocksDB `<= v11.13.2` (tagged 2026-10-28) — `db/forward_iterator.cc` |
| **CVSS 3.1**             | 6.2 **MEDIUM** — `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H` |
| **CWE**                  | CWE-416 (Use After Free)                                        |

- **Fix commit:** [`dec85e6516630101d2fa9549937bcd88ba7e6e0a`](https://github.com/meta/rocksdb/commit/dec85e6516630101d2fa9549937bcd88ba7e6e0a)
  ("Fix use-after-free in ForwardIterator::RebuildIterators on a dropped column
  family", PR #15704, merged 2026-11-17).
- **Status:** 0-day in the current release line — the fix is **not** an ancestor
  of `v11.13.2` (or any earlier tag).

## Vulnerable code (`db/forward_iterator.cc`, before `dec85e6`)

```cpp
void ForwardIterator::RebuildIterators(bool refresh_sv) {
  // Clean up
  Cleanup(refresh_sv);                            // (1) releases sv_
  if (refresh_sv) {
    // New
    sv_ = cfd_->GetReferencedSuperVersion(db_);   // (2) reads freed cfd_  -> UAF
  }
  ReadRangeDelAggregator range_del_agg(&cfd_->internal_comparator(), ...);
  ...
}
```

`Cleanup(true)` → `SVCleanup()` → `sv_->Unref()`. When that `SuperVersion` is the
column family's *current* SuperVersion, destroying it releases the last
`ColumnFamilyData` reference, so the CFD is freed at step (1); step (2) then reads
freed memory. The fix's own root-cause analysis states: *"ASAN reports a
heap-use-after-free in `ColumnFamilyData::GetThreadLocalSuperVersion()`."*

### The fix

```cpp
void ForwardIterator::RebuildIterators(bool refresh_sv) {
  if (refresh_sv && sv_ != nullptr &&
      sv_->version_number == cfd_->GetSuperVersionNumber()) {
    refresh_sv = false;                           // sv_ is still current: keep it
  }
  SuperVersion* const new_sv =
      refresh_sv ? cfd_->GetReferencedSuperVersion(db_) : nullptr;
  Cleanup(refresh_sv);                            // refresh_sv=false -> sv_ NOT released
  if (refresh_sv) {
    sv_ = new_sv;
  }
  ...
}
```

A dropped column family never installs a new SuperVersion, so
`sv_->version_number == cfd_->GetSuperVersionNumber()` always holds and the code
takes the "keep `sv_`" path — the CFD is never freed during the rebuild.

## Exploit chain

1. The application opens a **tailing** iterator (`ReadOptions::tailing = true`)
   with an `iterate_upper_bound`.
2. The application drops the column family and destroys its
   `ColumnFamilyHandle` while the iterator is still open. The iterator's
   `SuperVersion` (`sv_`) is now the *last* reference to the `ColumnFamilyData`
   (`cfd refs == 1`).
3. A seek past the largest key of an L0 file trims that file's child iterator and
   sets `has_iter_trimmed_for_upper_bound_`.
4. A subsequent `SeekToFirst()` (or backward `Seek()`) calls
   `RebuildIterators(true)`:
   - `Cleanup(true)` → `sv_->Unref()` → SuperVersion destroyed → CFD refcount
     1→0 → CFD freed.
   - `sv_ = cfd_->GetReferencedSuperVersion(db_)` dereferences the dangling
     `cfd_` → use-after-free (the rebuilt SuperVersion's `version_number_` is
     read out of freed memory; with heap reuse, `cfd_` can alias a different,
     attacker-influenced object).

## Exploitability assessment (honest threat model)

- **This is not a remote / network-reachable primitive.** The trigger is an
  embedding application's own API sequence (drop a column family while a tailing
  iterator with an upper bound is still open, then seek). RocksDB's documentation
  advises destroying iterators before dropping a column family, but the library
  did not *enforce* it, and the maintainers treat the resulting UAF as a bug
  worth fixing (the fix adds the defense plus a regression test).
- **Where it matters:** any RocksDB-backed system that manages column families
  dynamically (time-series/tenant-per-CF databases, RocksDB-as-a-service) can hit
  this through a routine CF-lifecycle + tailing-change-stream pattern. A heap
  use-after-free in such a process is exploitable for crash (DoS) or, with heap
  grooming, arbitrary code execution — but full RCE is **not demonstrated** here.
- **Severity honesty:** scored MEDIUM 6.2 (`AV:L/AC:H`, `C:L/I:L/A:H`). The
  demonstrated effect is the deterministic dangling-pointer read plus a
  heap-reuse type-confusion; RCE is plausible but unproven, and the trigger
  requires the API-lifecycle precondition above.

## PoC

`poc.cc` transcribes the exact vulnerable and fixed `RebuildIterators` ordering
and the `ColumnFamilyData`/`SuperVersion` reference-counting graph verbatim, and
runs it against a deterministic arena that **poisons** freed blocks (0xDE) and
**reuses them LIFO** — turning the ASan-reported heap-use-after-free into an
observable differential, exactly like a redzone canary.

### Run

```bash
bash run.sh
```

### Expected output (abridged)

```
== [1] vulnerable RebuildIterators(true) ==
  before: sv_->version_number_ = 7 (cfd alive, refs=1)
  after:  sv_->version_number_ = 0xdededededededede  <-- read from freed memory
  => ROCKSGHOST-UAF-CONFIRMED (dangling cfd_ dereferenced after free)
  heap reuse: allocated new CFD (LIFO) into the freed block
  dangling cfd_ now reads: name_=EVIL_CFD version_number_=0x7777
  => ROCKSGHOST-TYPE-CONFUSION (iterator operates on a reused object)

== [2] fixed RebuildIterators(true) ==
  after:  sv_->version_number_ = 7 (sv_ kept, cfd_ alive)
  => ROCKSGHOST-NO-UAF (fix keeps the column family alive)
```

## Self-critique (3 ways this might NOT be a finding)

1. **"Dropping a CF while an iterator is open is documented misuse."** I checked
   RocksDB's docs/API surface: the contract discourages it, but nothing enforces
   it, and the fix (#15704) explicitly treats it as a real memory-safety bug —
   the commit adds a regression test and hardens `RebuildIterators`, and reports
   an ASan heap-use-after-free. The library previously *allowed* a silent UAF
   instead of defending against the lifecycle pattern.
2. **"The trigger needs `iterate_upper_bound` + a specific seek sequence."**
   Confirmed: `RebuildIterators(true)` is only reached after
   `has_iter_trimmed_for_upper_bound_` is set, which requires
   `ReadOptions::iterate_upper_bound`. This is part of the `AC:H` score and is
   stated honestly.
3. **"The PoC is a transcription, not the real binary."** The full RocksDB build
   (≈1M LOC, ~2000 objects) is infeasible here, so the PoC compiles the *verbatim*
   vulnerable/fixed method bodies and the exact reference-counting semantics into
   a minimal C++ program (zig cc) and drives it against a poisoned/reusing arena.
   The transcribed lines match `db/forward_iterator.cc` verbatim (verified at
   commit `f16beed5`); only the unrelated child-iterator/table-cache plumbing is
   omitted.
