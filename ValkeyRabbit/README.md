# ValkeyRabbit — valkey script-debugger whole-server crash (SIGABRT) on partial read (CWE-617/400)

valkey's synchronous Lua script debugger reads client commands with
`readReadCommandInternal()` (`src/scripting_engine.c`), which asserts
`*argc == 0` on entry. When a command spans more than one `connRead()`, the
function parses the `*<count>\r\n` header, sets `*argc = count`, and then
reaches `goto keep_reading` because the rest of the command has not arrived —
without resetting `*argc`. The debugger loop appends more data and retries, but
`*argc` still holds `count`, so the assert fires on the retry. In **SYNC** mode
the assert runs in the **server** process, which exits with SIGABRT — a
whole-server crash triggered by a client that can enter the debugger and send a
command longer than 1024 bytes (or split by TCP framing).

| Product + version | CVSS 3.1 | CWE |
|---|---|---|
| valkey ≤ 9.1.3 (scripting_engine.c) | 5.9 MEDIUM `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H` | CWE-617 / CWE-400 |

## Fix commit
- **Fix:** [`7dfa61e04390990da64b9e982c3b0fc0da8c7c82`](https://github.com/valkey-io/valkey/commit/7dfa61e04390990da64b9e982c3b0fc0da8c7c82)
  "Script debugger: reset \*argc on partial-read exit to fix server crash in SYNC mode (#5127)".
- The fix adds `*argc = 0;` on the `keep_reading` exit so the retry re-enters
  cleanly. It is in **9.2.0-rc2** but **not** backported to the 9.1.x stable
  line (`9.1.3`). No CVE/GHSA.

## Vulnerable code (src/scripting_engine.c @ 41fb27b2)
```c
static robj **readReadCommandInternal(size_t *argc, robj **err) {
    serverAssert(argc != NULL && *argc == 0);      // line 749 — fires on retry
    ...
    *argc = atoi(plen);                             // line 771 — *argc = count
    if (*argc <= 0 || *argc > 1024) goto protoerr;
    ...
    while (largc < *argc) {
        ...
        if ((size_t)(p + slen + 2 - copy) > sdslen(copy))
            goto keep_reading;                      // line 789 — leaves *argc=count
        ...
    }
}
```

## Exploit chain
1. Client issues `SCRIPT DEBUG SYNC` then `EVAL` to enter the synchronous debugger.
2. The client sends a debugger command >1024 bytes (or one split by TCP framing),
   so `readReadCommandInternal()` parses `*<count>\r\n`, sets `*argc = count`, and
   returns via `keep_reading`.
3. The debugger loop retries with the same `*argc`; the entry assert
   `*argc == 0` fails → `abort()` → the valkey **server process dies (SIGABRT)**.

## Run
```
bash run.sh
```
Compiles and runs `valkeyrabbit.c` — a faithful model of the assert + header
parse + partial-body `keep_reading` exit, in a forked child: the vulnerable
path SIGABRTs, the fixed `*argc = 0` reset re-enters cleanly.
