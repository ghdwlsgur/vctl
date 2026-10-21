package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/cli"
	vspherecli "github.com/ghdwlsgur/vctl/internal/cli/vsphere"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cli.Version = version
	// Operator binary only: govmomi is too heavy for the fleet-wide agent.
	cli.Extensions = append(cli.Extensions, func(env cli.Env) *cobra.Command {
		return vspherecli.Cmd(env, func() string { return cli.Version })
	})
	if err := cli.Execute(); err != nil {
		if code, ok := cli.ChildExitCode(err); ok {
			os.Exit(code)
		}
		ui.Errorf(os.Stderr, "%v", err)
		os.Exit(1)
	}
}
