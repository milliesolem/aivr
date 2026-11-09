# RedisRabbit — Redis vector-sets FILTER: unbounded recursion → stack-overflow DoS

| product + version          | CVSS 3.1 | CWE |
|----------------------------|----------|-----|
| Redis Open Source **8.0.1 → 8.10.1** (Vector Sets module) | **6.5 MEDIUM** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` | **CWE-674** (uncontrolled recursion) → **CWE-400** DoS |

A crafted **JSON attribute** stored on a vector-set element makes the `VSIM … FILTER`
expression evaluator recurse without bound in its hand-rolled JSON parser
(`modules/vector-sets/fastjson.c`), exhausting the stack and crashing the **entire
`redis-server` process** with `SIGSEGV`. The Vector Sets data type is a built-in,
**auto-loaded** component of every Redis 8.0+ build (the JSON `FILTER` landed in 8.0.1),
so any authenticated client that can `VADD`/`VSETATTR` a value and then run `VSIM` with
a `FILTER` can take the whole instance down — including every other tenant's data, in
shared deployments.

**Status: fixed upstream in Redis 8.10.2** (security release, 2026-09-17), release note
*"Vector Sets: Deeply nested JSON used in Vector Set queries could cause the server to
crash"*, via commit `52194c8f604b` *"Limit Vector Sets JSON Parser Allowed Recursion
Depth"*. No dedicated CVE was published in the release notes. This PoC reproduces the
vulnerable (`src/`, ≤ 8.10.1) and fixed (`src-fixed/`, 8.10.2) trees verbatim.

> **Note on the `unstable` branch:** as of 2026-11-09 the development branch (`unstable`,
> Redis has no `main` branch) still carries the *unfixed* two-argument
> `jsonParseArrayToken(p,end)` — the 8.10.2 fix has not yet been forward-ported. The
> vulnerable tree in `src/` is therefore byte-identical to both Redis ≤ 8.10.1 *and*
> current `unstable`.

## The bug

`fastjson.c` is included into `expr.c` and implements the JSON field-value parser that
backs the `VSIM … FILTER` option. Unlike the *skipping* path (`jsonSkipBracketed`, which
counts `{}`/`[]` depth **iteratively**), the *value* path recurses once per nested array
with no depth counter:

```c
/* fastjson.c — vulnerable (Redis <= 8.10.1) */
static exprtoken *jsonParseArrayToken(const char **p, const char *end) {
    ...
    while (1) {
        exprtoken *ele = jsonParseValueToken(p,end);   /* line 286  <-- recursion */
        ...
    }
}
static exprtoken *jsonParseValueToken(const char **p, const char *end) {
    ...
    case '[':  return jsonParseArrayToken(p,end);      /* line 339  <-- mutual recursion */
    ...
}
```

`jsonParseArrayToken` ⇄ `jsonParseValueToken` form a mutual-recursion cycle with no depth
limit. A JSON attribute like `{"f": [[[[…]]]]}` recurses once per `[`, so ~100k nested
brackets (~200 KB) is enough to blow an 8 MB thread stack. `VSIM` evaluates the `FILTER`
against **every candidate element's attribute** during HNSW search, so a single stored
element is sufficient.

**The fix (8.10.2)** adds a `recursion_depth_t` counter and rejects at depth 1000:

```c
/* fastjson.c — fixed (Redis 8.10.2, commit 52194c8f604b) */
#define MAX_RECURSION_DEPTH_LIMIT 1000
static exprtoken *jsonParseValueToken(const char **p, const char *end, recursion_depth_t current) {
    if (current >= MAX_RECURSION_DEPTH_LIMIT) { ... return NULL; }   /* line 341 */
    ...
    case '[':  return jsonParseArrayToken(p,end,current);            /* line 350 */
}
```

## Exploit chain

1. `VADD myvset VALUES 1 0.5 pwned SETATTR '{"f": [[[[…300000×[ …]]]]}'`
   (or `VSETATTR myvset pwned '{"f": [[[[…]]]]}'`) — store a deeply-nested array as the
   `f` attribute. The attribute is an ordinary Redis string; the 512 MB default
   `proto-max-bulk-len` is far above the ~600 KB payload.
2. `VSIM myvset VALUES 1 0.9 COUNT 1 FILTER '.f'` — any filter referencing `.f`.
3. Per candidate: `vectorSetFilterCallback()` (`vset.c:805`) → `exprRun()`
   (`vset.c:811`) → `jsonExtractField()` (`expr.c:764`) → `jsonParseValueToken()`
   (`fastjson.c:333`) → `jsonParseArrayToken()` (`fastjson.c:270`) → … recursion …
4. Stack exhaustion → `SIGSEGV` → the **whole `redis-server` process dies** (data loss
   for every client/tenant on that instance).

The module is loaded by default: `src/Makefile` sets `-DINCLUDE_VEC_SETS=1` unless
`SKIP_VEC_SETS=yes`, and `src/server.c:8756` calls `moduleLoadInternalModules()` at
startup. `VSIM`/`VADD`/`VSETATTR` are not ACL-restricted by default.

## Exploitability assessment (honest threat model)

- **Preconditions:** (1) a Redis 8.0.1–8.10.1 build with the default Vector Sets module
  (the default); (2) an authenticated client with `VADD`/`VSETATTR` + `VSIM` access —
  i.e. the `default` user in any non-ACL setup, or any user granted `@write`/`@read`
  (the new commands fold into existing ACL categories per the 8.0 release notes).
- **Impact:** full-process crash (availability only, no confidentiality/integrity
  impact). In shared/multi-tenant Redis (very common) this is a **cross-tenant DoS**: one
  tenant crashes the instance for everyone. A running instance loses all un-replicated
  in-memory data.
- **Not exploitable for:** code execution, memory disclosure, or data tampering — the
  failure mode is a deterministic stack overflow, not a controlled write.

## Run

```bash
bash run.sh
```

Compiles `harness.c` twice — against the **verbatim** vulnerable tree (`src/` = Redis
`main`/≤8.10.1 `expr.c` + `fastjson.c`) and the **verbatim** fixed tree (`src-fixed/` =
8.10.2) — with `musl-gcc`, then drives both with the same 300k-nesting attribute:

```
=== [1] VULNERABLE (Redis <= 8.10.1): 300000 nested arrays ===
Segmentation fault                                    # stack overflow, rc=139
=== [2] FIXED (Redis 8.10.2): 300000 nested arrays ===
exprRun returned 0 (no crash)                         # rejected at depth 1000, rc=0
RESULT: PASS — differential reproduced.
```

`run.sh` exits 0 only when the vulnerable binary crashes with `SIGSEGV` **and** the fixed
binary survives the identical input. The harness drives the *actual* Redis parser source;
the only shims are the five `RedisModule_*` allocation symbols the module API supplies in
a real server.

## Self-critique — three ways this might NOT fire (and how each was checked)

1. **"There's a depth limit I missed."** `jsonSkipBracketed`/`jsonSkipValue` (the skip
   path) use an explicit `depth` counter, but the *parse* path
   (`jsonParseValueToken` ⇄ `jsonParseArrayToken`) had none before 8.10.2 — confirmed by
   reading `fastjson.c:270-352` and, empirically, by the SIGSEGV at ~100k depth on the
   ≤8.10.1 tree (and the clean rejection at depth 1000 on the 8.10.2 tree).
2. **"The attribute is size-capped."** `VSETATTR`/`VADD SETATTR` accept an ordinary
   Redis bulk string; the default `proto-max-bulk-len` is 512 MB. The ~200 KB (crash
   threshold) and ~600 KB (PoC) payloads are both far below it. No vector-set-specific
   cap exists (`vset.c` stores the attribute verbatim via `RedisModule_StringPtrLen`).
3. **"A crash in the filter wouldn't take down the server."** `VSIM` runs the filter
   (default) on a worker thread, but `SIGSEGV` is process-wide and Redis installs no
   `SIGSEGV` handler that survives it — the process aborts. There is no guard around
   `exprRun` in `vectorSetFilterCallback` (`vset.c:805-812`).

## References

- Fix commit: https://github.com/redis/redis/commit/52194c8f604b8b738b62a477d6bfdf65fb5c622d
- Introducing commit (fast JSON filter): `11947d8892d9` (#13959, 2025-05-05)
- Redis 8.10.2 release notes:
  https://raw.githubusercontent.com/redis/redis/8.10.2/00-RELEASENOTES
