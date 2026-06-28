package main

import (
	"os"

	"github.com/ghdwlsgur/vctl/internal/cli"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cli.Version = version
	if err := cli.Execute(); err != nil {
		if code, ok := cli.ChildExitCode(err); ok {
			os.Exit(code)
		}
		ui.Errorf(os.Stderr, "%v", err)
		os.Exit(1)
	}
}
