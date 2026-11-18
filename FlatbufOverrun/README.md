# FlatbufOverrun — FlatBuffers reflection parser out-of-bounds write (CWE-787)

| Field | Value |
| --- | --- |
| **Product / version** | [google/flatbuffers](https://github.com/google/flatbuffers) C++ — every release through **v25.12.19-2026-02-06** (`95fda8c`, 2026-02-06), the latest tagged release |
| **CVSS 3.1** | **8.8 HIGH** `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-787 (out-of-bounds write) |
| **Fix** | [`8a12183`](https://github.com/google/flatbuffers/commit/8a12183c3bf2fc39a5c6c32307b81d947bc37e22) (PR [#8988](https://github.com/google/flatbuffers/pull/8988), 2026-04-02) — **master only, no release contains it** |
| **Vulnerable code** | `src/idl_parser.cpp:4132` (in `StructDef::Deserialize`) |

## Summary

`StructDef::Deserialize` rebuilds a struct's field ordering when a binary
reflection schema (`.bfbs`) is loaded. It sizes a temporary index vector to the
field count and then indexes it by each field's **reflection `id`** — a raw
`uint16` read from the buffer with no bounds check:

```cpp
// src/idl_parser.cpp:4129-4132 (v25.12.19-2026-02-06)
const auto& of = *(object->fields());
auto indexes = std::vector<uoffset_t>(of.size());
for (uoffset_t i = 0; i < of.size(); i++) indexes[of.Get(i)->id()] = i;
```

`reflection.fbs` declares `Field.id` as a plain `ushort` with no relationship to
the parent `Object`'s field count. The flatbuffers `Verifier` (which runs first
in `Parser::Deserialize`) only checks *structural* validity — offsets in range,
scalar types correct — so a `.bfbs` whose field carries `id >= field_count`
passes verification and reaches the unguarded write. `indexes[field_id]` then
writes `sizeof(uoffset_t)` bytes past the heap vector, at an offset the attacker
chooses (up to `0xFFFF * 4` ≈ 256 KiB), with a small attacker-influenceable
value (the field's loop index).

The upstream fix bounds-checks the id before indexing:

```cpp
for (uoffset_t i = 0; i < of.size(); i++) {
  uint16_t field_id = of.Get(i)->id();
  if (field_id >= of.size()) {
    parser.error_ = "Field ID " + std::to_string(field_id) +
                    " exceeds field count " + std::to_string(of.size());
    return false;
  }
  indexes[field_id] = i;
}
```

## Exploit chain

1. The victim parses an attacker-supplied `.bfbs` with the reflection API —
   `flatc` (build-time / supply-chain), or any runtime use of
   `flatbuffers::Parser::Deserialize`.
2. `Parser::Deserialize(buf, size)` (`:4412`) verifies the buffer
   (`VerifySchemaBuffer`), then `GetSchema(buf)` (`:4429`).
3. `Parser::Deserialize(schema)` (`:4433`) iterates `schema->objects()` and calls
   `struct_def->Deserialize(*this, *it)` (`:4476`).
4. `StructDef::Deserialize` (`:4124`) runs the unguarded loop at `:4132` and
   writes `indexes[field_id]` out of bounds for any `field_id >= of.size()`.
5. Result: a heap out-of-bounds write. With a small id the write corrupts an
   adjacent heap allocation (demonstrated via a redzone canary); with
   `id = 0xFFFF` it smashes ~256 KiB past the buffer and the process dies with
   SIGSEGV.

## Proof of concept

`poc.cc` compiles the **real project source** — `src/idl_parser.cpp`,
`src/reflection.cpp`, `src/util.cpp` and `include/flatbuffers/*.h` vendored
verbatim from tag `v25.12.19-2026-02-06` — with zig cc, and drives
`Parser::Deserialize` on a structurally-valid `.bfbs` built with the library's
own `reflection::CreateSchema`/`CreateField` builders (field `id` = attacker
value). A redzone-canary global `operator new`/`delete` turns the out-of-bounds
write into a deterministic observable without ASan.

`run.sh` builds both binaries (vulnerable release source, and the same source
with upstream fix `8a12183` applied) and runs them on the identical buffer.

```
bash run.sh
```

Expected output (this host, zig cc 0.14 / libc++):

```
--- VULNERABLE (v25.12.19-2026-02-06) ---
[canary] field_id=0x0001 (1)  Deserialize=true
       *** OOB WRITE DETECTED: redzone byte +4 corrupted 0xcd -> 0x00
FLATBUFFERS-OOB-CONFIRMED

--- VULNERABLE, id=0xFFFF (large OOB write -> SIGSEGV) ---
[huge-id] child killed by signal 11 (SIGSEGV) — OOB write hit unmapped memory

--- FIXED (8a12183) ---
[canary] field_id=0x0001 (1)  Deserialize=false
       parser.error_ = "Field ID 1 exceeds field count 1"
       no redzone corruption (in-bounds)
```

The `FLATBUFFERS-OOB-CONFIRMED` marker (only emitted by the vulnerable build)
proves the out-of-bounds write; the fixed build rejects the same input with a
bounds error and performs no write.

## Exploitability / threat model

- **Who is harmed:** anyone who loads a `.bfbs` reflection schema from an
  untrusted source — `flatc` invoked on a malicious schema (CI/supply-chain
  compromise, the same surface as the adjacent `codegen` injection fix
  [#8964](https://github.com/google/flatbuffers/pull/8964)), or an application
  that uses FlatBuffers reflection to interpret schemas at runtime.
- **Impact:** heap out-of-bounds **write** (CWE-787) with an attacker-controlled
  offset and a small influenceable value. Demonstrated: deterministic memory
  corruption and a SIGSEGV crash. Full arbitrary-code execution is *not*
  demonstrated here — the write value is a bounded loop index, so pivoting it
  into control-flow hijack would require heap grooming — but the primitive is
  the classic corrupt-a-length/pointer-next-to-the-vector shape.
- **Boundary:** the `id` value comes straight from the attacker-controlled
  binary, passes the verifier, and is used as an array index without validation.

## Why it might not work (and how each was checked)

1. **"The verifier rejects a bad field id before `Deserialize`."** Checked:
   `Parser::Deserialize` (`:4412`) runs `reflection::VerifySchemaBuffer`
   (`:4424`), which validates structural layout only — the reflection schema's
   `Field.id` is a scalar with no cross-field constraint. The PoC builds the
   `.bfbs` with the library's own builders and it is accepted.
2. **"The fix is already released."** Checked the two latest tags:
   `v25.12.19` (`282dcb1`, 2025-12-19) and `v25.12.19-2026-02-06`
   (`95fda8c`, 2026-02-06) both still contain the unguarded
   `indexes[of.Get(i)->id()] = i;` line; `8a12183` (2026-04-02) is not an
   ancestor of either tag. No newer release exists.
3. **"It's only a read, not a write."** The vulnerable line is an assignment
   `indexes[...] = i`, i.e. a write. The redzone-canary allocator observes the
   write directly (`0xcd -> 0x00`), and `id=0xFFFF` produces a SIGSEGV.

## Files

- `poc.cc` — driver (crafts the malicious `.bfbs`, redzone-canary allocator,
  canary + huge-id demonstrations)
- `run.sh` — builds the vulnerable and fixed binaries with zig cc and runs the
  differential
- `fix.patch` — the exact upstream fix `8a12183`
- `src/` — `idl_parser.cpp`, `reflection.cpp`, `util.cpp` vendored verbatim from
  `v25.12.19-2026-02-06`
- `include/flatbuffers/` — project headers vendored from the same tag
- `finding.json` — machine-checkable evidence contract
