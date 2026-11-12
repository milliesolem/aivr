# TunnelPicklock — cloudflared Access bypass via matrix-path parameters (VULN-170057)

| | |
|---|---|
| Product + version | cloudflare/cloudflared 2026.10.0–2026.10.7, path normalization enabled (opt-in `--disable-path-normalization=false`, or remotely-managed tunnels with normalization on) |
| CVSS | 6.8 Medium — `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N` |
| CWE | CWE-862 (Missing Authorization) / CWE-180 (Incorrect Handling of URL Path Separators) |

**Fix:** commit `3106f9499d6a23e2f87ec5267eb4771b507a4d1f` — *"VULN-170057: Don't bypass
access with matrix parameters"* (2026-11-04, Cloudflare's internal VULN- security tracker).
**Unreleased** as of 2026-11-12: the latest public release `2026.10.7` (2026-10-30) predates it.
Vulnerable parent commit (used for citations): `872b241f94871665c1c157adefcf90c11f0ead96`.

**Normalization status:** the vulnerable `canonicalPathForMatching` was introduced by the
VULN-141859 fix (2026-09-29) **disabled by default** ("will only enable it in future releases"),
controlled by `--disable-path-normalization` (default `true`) / `TUNNEL_DISABLE_PATH_NORMALIZATION`.
The VULN-170057 bypass therefore affects normalization-enabled deployments; the same matrix/dot
payloads against normalization-disabled deployments fall into the older VULN-141859 class, which
the flag explicitly documents as a risk. Either way the Access-protection contract is breakable.

## The bug

cloudflared picks the ingress rule for a request by canonicalizing the path and matching rules
in order (`Ingress.FindMatchingRule`). The vulnerable canonicalization
(`canonicalPathForMatching`) runs on `url.URL.Path` — which `net/url` has **already
percent-decoded** — and does not strip Servlet-style **matrix parameters** (path segments
delimited by `;`):

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

Consequences (all verified by the PoC):

| request | vulnerable match | origin (Servlet-style) serves |
|---|---|---|
| `/public/.;x/../admin` | `path.Clean` pops `.;x` and `..` → `/public/admin` → **non-Access `/public` rule** | `/admin` |
| `/admin;x=%2f..%2fpublic` | `net/url` decodes to `/admin;x=/../public` → `path.Clean` → `/public` → **non-Access `/public` rule** | `/admin` |
| `/public\..;x\admin` | backslash → `/public/..;x/admin` → `path.Clean` → `/public/admin` → **non-Access rule** | `/admin` |

The request forwarded to the origin is **never modified** — so a Tomcat/Jetty/Servlet-style
origin (which strips matrix parameters and resolves dot-segments itself) serves the
Access-protected `/admin` resource **without any Access authentication**. That is exactly the
bypass Cloudflare fixed in VULN-170057.

## The fix

```go
// fixed (ingress/ingress.go @ 3106f9499d6a)
func canonicalPathForMatching(escapedPath string) string {
	return normalizePath(escapedPath,
		stripPathParameters,     // strip ';' params FIRST, on the ESCAPED path
		decodePathForMatching,   // then percent-decode
		normalizeSeparators,     // then backslash -> slash
		resolveDotSegments,      // then path.Clean + trailing-slash rule
	)
}
```

plus a second **decode-first interpretation** re-check in `findMatchingRuleWithPathNormalization`
(after the primary match, an alternate normalization `normalizeSeparators → stripPathParameters →
resolveDotSegments` is also matched; if *either* interpretation lands on an Access-required rule,
Access is enforced). The commit message documents why both interpretations are needed
(`/public%5C..;x%5Cadmin`).

## Exploit chain

1. Deploy/observe a tunnel with path normalization enabled (`--disable-path-normalization=false`
   or a remotely-managed tunnel whose orchestrator enables it) whose ingress has a public path
   rule before an Access-gated rule (the standard layout: `/public` open, `/admin` behind
   Cloudflare Access).
2. Send `GET /public/.;x/../admin` (or the encoded/backslash variants) to the tunnel.
3. cloudflared matches the request to the non-Access `/public` rule and proxies it unauthenticated;
   the origin normalizes the path and serves the protected `/admin` resource.

## Exploitability assessment

- Unauthenticated, single request, no special tooling. High confidentiality impact when the
  protected path serves sensitive data or admin surfaces (S:C because the origin is a different
  security scope than the Access policy).
- **AC:H**: the vulnerable normalization is opt-in in all public releases (the VULN-141859
  normalization shipped 2026-09-29 disabled by default, to be enabled in future releases), so the
  affected population today is normalization-enabled deployments.
- Requires the origin/downstream hop to use matrix-parameter + dot-segment semantics (Servlet
  containers, Jetty, Tomcat and compatible stacks — extremely common); if the origin treats the
  raw path literally, the bypass is neutralized at the origin level (documented in the commit).
- Cloudflare has an existing internal track record of this exact class (see the in-repo
  `DisablePathNormalization` escape hatch that restores the earlier VULN-141859 bypass), which is
  why the fix is VULN-tracked.

## Run

```
bash run.sh
```

The harness compiles **both** sides verbatim from upstream:

- **vulnerable** — `FindMatchingRule`, `canonicalPathForMatching`, `rulesRequireAccess`,
  `matchHost` and `Rule.Matches` from parent commit `872b241f9487` (`ingress/ingress.go`,
  `ingress/rule.go`), with minimal type stubs mirroring upstream field names;
- **fixed** — `FindMatchingRule(*url.URL)`, `findMatchingRuleWithPathNormalization`,
  `canonicalPathForMatching` (pipeline), `normalizePath`, `decodePathForMatching`,
  `normalizeSeparators`, `resolveDotSegments`, `stripPathParameters` from the fix commit;
- **config** — user `path:` strings compile as raw Go regexps, exactly as `validateIngress` does.

Expected output: all four crafted payloads match rule #0 (`NO Access`) under the vulnerable code
and rule #1 (`Access REQUIRED`) under the fixed code → `DIFFERENTIAL PASS`.

## References

- Fix commit: https://github.com/cloudflare/cloudflared/commit/3106f9499d6a23e2f87ec5267eb4771b507a4d1f
- Vulnerable parent: https://github.com/cloudflare/cloudflared/commit/872b241f94871665c1c157adefcf90c11f0ead96
- Vulnerable matcher: https://github.com/cloudflare/cloudflared/blob/872b241f94871665c1c157adefcf90c11f0ead96/ingress/ingress.go
- Latest release (vulnerable): https://github.com/cloudflare/cloudflared/releases/tag/2026.10.7
