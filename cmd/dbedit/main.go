// Command dbedit is a small maintenance tool for operator-managed inventory
// columns that `vctl sync` would otherwise clobber (dc, ssh user). It reuses the
// vctl app for Vault auth + dynamic DB creds.
//
//	go run ./cmd/dbedit <hostname>=<value> [<hostname>=<value> ...]      # dc (default)
//	go run ./cmd/dbedit -col user <hostname>=<value> [ ... ]             # ssh user
//	go run ./cmd/dbedit -col ips  <hostname>=<ip,ip,...> [ ... ]         # extra IPs
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
)

func main() {
	col := flag.String("col", "dc", "field to set: dc | user | name (rename) | ips (extra IPs, comma-separated)")
	flag.Parse()

	set, ok := map[string]func(context.Context, *store.Store, string, string) (bool, error){
		"dc":   func(ctx context.Context, st *store.Store, h, v string) (bool, error) { return st.SetDC(ctx, h, v) },
		"user": func(ctx context.Context, st *store.Store, h, v string) (bool, error) { return st.SetUser(ctx, h, v) },
		"name": func(ctx context.Context, st *store.Store, h, v string) (bool, error) { return st.Rename(ctx, h, v) },
		"ips": func(ctx context.Context, st *store.Store, h, v string) (bool, error) {
			return st.SetExtraIPs(ctx, h, splitIPs(v))
		},
		"del": func(ctx context.Context, st *store.Store, h, _ string) (bool, error) { return st.Delete(ctx, h) },
	}[*col]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown -col %q (want dc|user|name|ips|del)\n", *col)
		os.Exit(2)
	}
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: dbedit [-col dc|user|name|ips] <hostname>=<value> [ ... ]\n")
		fmt.Fprintf(os.Stderr, "       dbedit -col del <hostname> [ ... ]   # remove from inventory\n")
		os.Exit(2)
	}

	ctx := context.Background()
	a, err := app.New()
	if err != nil {
		fatal(err)
	}
	if err := a.EnsureLogin(ctx); err != nil {
		fatal(err)
	}
	st, err := a.OpenStore(ctx, true)
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	rc := 0
	for _, arg := range flag.Args() {
		host, val, ok := strings.Cut(arg, "=")
		if !ok {
			host = arg // del takes a bare hostname (no =value)
		}
		if host == "" || (*col != "del" && val == "") {
			fmt.Fprintf(os.Stderr, "skip %q (need host=value)\n", arg)
			rc = 1
			continue
		}
		updated, err := set(ctx, st, host, val)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "ERR  %s: %v\n", host, err)
			rc = 1
		case !updated:
			fmt.Fprintf(os.Stderr, "MISS %s (no such host)\n", host)
			rc = 1
		case *col == "del":
			fmt.Printf("OK   %s deleted\n", host)
		default:
			fmt.Printf("OK   %s %s -> %s\n", host, *col, val)
		}
	}
	os.Exit(rc)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fatal:", err)
	os.Exit(1)
}

// splitIPs parses a comma-separated IP list, trimming blanks (so "" clears).
func splitIPs(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
