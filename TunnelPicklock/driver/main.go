// TunnelPicklock exploit driver.
//
// This is NOT a re-implementation: it imports the REAL cloudflared packages
// (github.com/cloudflare/cloudflared/ingress + ingress/middleware) from the
// vulnerable release 2026.10.7 (commit 872b241f9487) via a go.mod replace
// directive, builds an Ingress from a real config.Configuration through the
// real ingress.ParseIngress (regexp compilation, origin services, and the real
// Access JWTValidator middleware), and dispatches requests with the exact
// control flow of proxy/proxy.go at that commit:
//
//   proxy/proxy.go:135  rule, ruleNum := p.ingressRules.FindMatchingRule(req.Host, req.URL.Path)
//   proxy/proxy.go:88   applyIngressMiddleware: for _, handler := range rule.Handlers {
//                          result, err := handler.Handle(r.Context(), r)
//                          if result.ShouldFilterRequest { _ = w.WriteRespHeaders(result.StatusCode, nil); return }
//   proxy/proxy.go:235  proxyHTTPRequest -> httpService.RoundTrip(req)   (path untouched)
//
// The Python exploit.py script stands up a Servlet-style origin backend and
// drives this driver to demonstrate the Access bypass against the real code.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/cloudflare/cloudflared/config"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/rs/zerolog"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: driver <backend-url> <listen-addr>")
		os.Exit(2)
	}
	backendURL, listenAddr := os.Args[1], os.Args[2]

	// Real config struct, exactly what an operator's config file would carry:
	//   ingress:
	//     - path: /public          service: http://backend
	//     - path: /admin           service: http://backend
	//       originRequest:
	//         access: { required: true, teamName: example }
	//     - service: http_status:503
	conf := &config.Configuration{
		Ingress: []config.UnvalidatedIngressRule{
			{Path: "/public", Service: backendURL},
			{Path: "/admin", Service: backendURL,
				OriginRequest: config.OriginRequestConfig{
					Access: &config.AccessConfig{Required: true, TeamName: "example-team"},
				}},
			{Service: "http_status:503"},
		},
	}

	// Real ingress construction: validateIngress compiles the path regexps,
	// builds the origin services, and wires the real Access JWTValidator
	// middleware onto the /admin rule.
	ing, err := ingress.ParseIngress(conf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ParseIngress failed: %v\n", err)
		os.Exit(2)
	}
	// Path normalization ENABLED: in released binaries this is the vulnerable
	// state when the flag is not set (--disable-path-normalization=false /
	// remotely-managed tunnels with normalization on). The CLI defaults the
	// flag to true, but ParseIngress leaves DisablePathNormalization=false.
	ing.DisablePathNormalization = false

	// Real origin startup, as cloudflared does before serving requests
	// (ingress.StartOrigins -> rule.Service.start -> newHTTPTransport).
	log := zerolog.New(io.Discard)
	if err := ing.StartOrigins(&log, context.Background().Done()); err != nil {
		fmt.Fprintf(os.Stderr, "StartOrigins failed: %v\n", err)
		os.Exit(2)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// === verbatim flow from proxy/proxy.go @ 872b241f9487 ===
		rule, ruleNum := ing.FindMatchingRule(r.Host, r.URL.Path)
		fmt.Printf("[driver] %s %s -> rule #%d (accessRequired=%v)\n",
			r.Method, r.URL.RequestURI(), ruleNum, rule.Config.Access.Required)
		for _, h := range rule.Handlers {
			result, err := h.Handle(r.Context(), r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if result.ShouldFilterRequest {
				fmt.Printf("[driver]   filtered by middleware %q: %s (%d)\n",
					h.Name(), result.Reason, result.StatusCode)
				w.WriteHeader(result.StatusCode)
				return
			}
		}
		switch originProxy := rule.Service.(type) {
		case ingress.HTTPOriginProxy:
			// httpService.RoundTrip rewrites scheme/host only; the request
			// PATH reaches the origin untouched.
			resp, err := originProxy.RoundTrip(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			buf := make([]byte, 32*1024)
			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					if _, werr := w.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		default:
			http.Error(w, "non-HTTP origin", http.StatusNotImplemented)
		}
	})

	fmt.Printf("[driver] cloudflared %s (commit %s) ingress proxy listening on %s\n",
		ingressVersion(), "872b241f94871665c1c157adefcf90c11f0ead96", listenAddr)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func ingressVersion() string { return "2026.10.7" }
