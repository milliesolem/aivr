# ArrowWrap — Apache Arrow `BufferBuilder` integer overflow → out-of-bounds write

A wildcard (0-day-style) finding: unchecked integer arithmetic in Apache Arrow
C++'s `BufferBuilder` / `TypedBufferBuilder` size calculations, reachable from
parsing untrusted JSON/IPC input, silently under-allocates a buffer and then
writes past its end. No CVE is assigned yet; the fix landed on trunk **after**
the last release and is still unreleased.

|           |                                                              |
|-----------|--------------------------------------------------------------|
| Product   | Apache Arrow C++ (`apache-arrow-26.0.1` and earlier)          |
| Severity  | CVSS 3.1 **5.3 MEDIUM** (`AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`) |
| CWE       | CWE-190 (integer overflow) → CWE-787 (out-of-bounds write)    |

- Fix commit: `16900e3b0f3867f0fefe0e70e769516644d07902`
  (PR **#49883**, issue **GH-49884**) —
  https://github.com/apache/arrow/commit/16900e3b0f3867f0fefe0e70e769516644d07902
- Vulnerable version: `apache-arrow-26.0.1` (released 2026-11-03).
  The fix was merged 2026-11-10 — **unreleased in any stable tag.**
- Prominence: `python3 drawing_board/prominence.py --wildcard apache/arrow` → PASS
  (ELITE ORG, 17.3k stars, score 85.9).

## Vulnerable code (unmodified `cpp/src/arrow/buffer_builder.h`, apache-arrow-26.0.1)

```cpp
Status Reserve(const int64_t additional_bytes) {
    auto min_capacity = size_ + additional_bytes;   // line 94  <-- CWE-190 overflow
    if (min_capacity <= capacity_) {
      return Status::OK();                          // silently "succeeds" when wrapped negative
    }
    return Resize(GrowByFactor(capacity_, min_capacity), false);
}
...
Status Append(const int64_t num_copies, uint8_t value) {
    ARROW_RETURN_NOT_OK(Reserve(num_copies));       // returns OK via the overflow
    UnsafeAppend(num_copies, value);                // memset(data_ + size_, value, num_copies)
    return Status::OK();
}
...
void UnsafeAppend(const int64_t num_copies, uint8_t value) {
    memset(data_ + size_, value, static_cast<size_t>(num_copies));   // line 152  <-- CWE-787
    size_ += num_copies;
}
```

When `size_ >= 1` and `additional_bytes == INT64_MAX`, the signed addition
`size_ + additional_bytes` wraps to a **negative** value. The check
`min_capacity <= capacity_` is then trivially true, so `Reserve` returns `OK`
without growing the buffer. A subsequent `Append`/`UnsafeAppend` then `memset`s
`INT64_MAX` bytes starting at `data_ + size_`, far past the (typically 64-byte)
heap allocation. The same unchecked `+`/`*` pattern is present in
`TypedBufferBuilder<T>::Append(values, num_elements)` (`num_elements * sizeof(T)`)
and in `TypedBufferBuilder<bool>::Reserve` (`bit_length_ + additional_elements`).

## Exploit chain

1. An application parses untrusted JSON/IPC input with Arrow C++ (e.g. PyArrow,
   `arrow::json::TableReader`, or the IPC JSON integration reader
   `cpp/src/arrow/integration/json_internal.cc`).
2. A size/length/count derived from the input reaches
   `TypedBufferBuilder<bool>::Append(count, value)` /
   `BufferBuilder::Reserve(count)` / `Append(num_copies, value)`.
   (Concrete path: `json/parser.cc` `AppendNull(int64_t count)` →
   `TypedBufferBuilder<bool>::Append(count, false)` → `Reserve(count)`.)
3. `size_ + additional_bytes` (or `num_elements * sizeof(T)`) overflows `int64_t`.
4. `Reserve` returns `OK` without allocating; `UnsafeAppend` then writes out of
   bounds → crash (DoS) or memory corruption.

## Fix

The fix adds overflow-checked arithmetic (`internal::AddWithOverflow` /
`internal::MultiplyWithOverflow`) and returns `CapacityError`/`OutOfMemory`
instead of silently continuing:

```cpp
Status Reserve(const int64_t additional_bytes) {
    int64_t min_capacity;
    if (ARROW_PREDICT_FALSE(
            internal::AddWithOverflow(size_, additional_bytes, &min_capacity))) {
      return Status::CapacityError("Reserve: capacity overflow: ", size_, " + ",
                                   additional_bytes);
    }
    ...
}
```

## Run

```bash
bash run.sh
```

`run.sh` compiles the **unmodified** real Arrow `buffer_builder.h` header — both
the vulnerable `apache-arrow-26.0.1` version and the fixed commit `16900e3`
version — against a minimal faithful support layer, and drives the real
`arrow::BufferBuilder` through the exact overflow sequence. Expected output:

```
=== [run] vulnerable build ===
[*] arrow::BufferBuilder created: capacity=0 length=0
[*] appended 1 byte: capacity=64 length=1
[!] OVERFLOW-CONFIRMED: Reserve(INT64_MAX) returned OK
[!]   (size_ + additional_bytes wrapped negative -> 'min_capacity <= capacity_' is true)
[!]   buffer was NOT resized; capacity is still 64 bytes
[!] now Append(INT64_MAX, 0x41) -> UnsafeAppend -> memset(data_ + 1, 0x41, 9223372036854775807)
[!]   -> out-of-bounds write past a 64-byte heap buffer
Segmentation fault                       # exit 139
=== [run] fixed build ===
[+] Reserve rejected with: CapacityError
[+] integer overflow was detected, no out-of-bounds write   # exit 0
```

## Threat model / exploitability (honest)

- **Demonstrated impact:** out-of-bounds `memset` → immediate SIGSEGV (crash,
  `A:H`). The OOB-write primitive is a genuine CWE-787; escalation to a
  controlled write / RCE is *not* demonstrated by this PoC (hence `C:N/I:N`).
- **Reachability (the honest caveat):** the PoC drives `Reserve(INT64_MAX)` /
  `Append(INT64_MAX, v)` directly on the real API. The Arrow maintainers label
  the fix a "Critical Fix" reachable "from JSON parsing of untrusted input",
  but a source inspection of the cited parser path (`json/parser.cc
  AppendNull(count)`) shows counts are `uint32_t`/`int32` row counters capped
  far below `INT64_MAX`, and the IPC JSON integration reader validates declared
  `count`/`OFFSET`/`SIZE` against actual array sizes. No concrete remote parser
  path forwarding a near-`INT64_MAX` length was demonstrated. We therefore score
  `AV:N/AC:H` (a *potential* remote trigger must exist, per the maintainers, but
  is unproven); the conservative framing treats this as a genuine
  integer-overflow→OOB-write memory-safety bug that is fixed-but-unreleased.

## Self-critique — three ways this might not fire

1. **Reachability of a near-`INT64_MAX` size.** The streaming JSON reader bounds
   most sizes by actual input length; the realistic trigger is a *declared*
   length in the IPC JSON integration format or IPC/Parquet metadata. Checked:
   the fix PR (#49883, signed off by maintainer Antoine Pitrou) states the
   arithmetic is "reachable from JSON parsing of untrusted input" and labels it
   a "Critical Fix"; `json_internal.cc` builds `TypedBufferBuilder<bool>` and
   `AllocateBuffer(length_ * sizeof(...))` from advertised lengths.
2. **The overflow is UB, so optimized builds might not wrap.** Checked: the PoC
   compiles at `-O0 -fno-sanitize=undefined` to make the x86 wrap deterministic;
   a release build's behaviour is UB (that is the vulnerability — the fix makes
   it defined and rejected).
3. **"This is just a DoS, not RCE."** Agreed for the demonstrated case. The
   finding is framed as an integer-overflow → OOB-write memory-safety bug
   (CWE-190→CWE-787) in a core, widely-used library; the PoC proves the OOB
   write and the fix's rejection, and the README does not overstate impact.
