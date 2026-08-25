// vctl-agent is the fleet-host slice of vctl: the systemd daemons and login
// hooks, without the operator commands. See internal/cli.NewAgentRoot for what
// is in it and why the split exists.
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
	if err := cli.ExecuteAgent(); err != nil {
		if code, ok := cli.ChildExitCode(err); ok {
			os.Exit(code)
		}
		ui.Errorf(os.Stderr, "%v", err)
		os.Exit(1)
	}
}
