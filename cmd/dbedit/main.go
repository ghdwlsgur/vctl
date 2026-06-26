// Command dbedit is a small maintenance tool for operator-managed inventory
// columns that `vctl sync` would otherwise clobber (currently: dc). It reuses
// the vctl app for Vault auth + dynamic DB creds.
//
//	go run ./cmd/dbedit <hostname>=<dc> [<hostname>=<dc> ...]
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/app"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dbedit <hostname>=<dc> [<hostname>=<dc> ...]")
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
	for _, arg := range os.Args[1:] {
		host, dc, ok := strings.Cut(arg, "=")
		if !ok || host == "" || dc == "" {
			fmt.Fprintf(os.Stderr, "skip %q (need host=dc)\n", arg)
			rc = 1
			continue
		}
		updated, err := st.SetDC(ctx, host, dc)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "ERR  %s: %v\n", host, err)
			rc = 1
		case !updated:
			fmt.Fprintf(os.Stderr, "MISS %s (no such host)\n", host)
			rc = 1
		default:
			fmt.Printf("OK   %s -> %s\n", host, dc)
		}
	}
	os.Exit(rc)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fatal:", err)
	os.Exit(1)
}
