package main

import (
	"fmt"
	"os"

	"github.com/ghdwlsgur/vctl/internal/cli"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cli.Version = version
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
