package cli

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/mcp"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// mcpCmd runs the MCP server in internal/mcp. Of the 450 lines that used to
// live here, these were the only ones that were a command; the rest were a
// JSON-RPC server, and being in this package let it grow private wiring — it
// took env as a parameter and never used it, building its own app instead, so
// the fake app every other command honours never reached the tools. What the
// server borrows from the CLI is now stated in mcp.Deps.
func mcpCmd(env CommandEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run a read-only MCP server (stdio) exposing the inventory to AI agents",
		Long: `mcp runs a Model Context Protocol server over stdio so an AI agent
(e.g. Claude Code) can query the vctl inventory.

Read-only tools: vctl_list, vctl_resolve, vctl_whoami, vctl_access_log. Tools
run as your current vctl identity — Vault policies and app RBAC still apply.
Auth is non-interactive (cached token / AppRole); it never prompts.

Wire it into Claude Code:
  claude mcp add vctl -- vctl mcp`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcp.Serve(cmd.Context(), os.Stdin, os.Stdout, mcp.Deps{
				Version:   Version,
				NewApp:    mcpApp(env),
				Connector: newConnector,
				HostStatus: func(w store.ServerWithStatus) string {
					return ui.StripANSI(liveStatus(w, false)) // MCP reads the live store
				},
			})
		},
	}
}

// mcpApp builds the app a tool call runs as — through the same seam every
// other command uses, so tests reach these tools with the same fake app —
// with auth pinned to AppRole. A lapsed session then re-auths
// non-interactively or errors, and never emits a login prompt that would
// corrupt the stdio JSON-RPC channel.
//
// Pinning the method is deliberate where App.Interactive alone would not be
// enough: the non-interactive login order still ends on the configured
// method, and userpass would read the prompt's answer off the same stdin the
// protocol runs on.
func mcpApp(env CommandEnv) func() (*app.App, error) {
	return func() (*app.App, error) {
		a, err := env.newApp()
		if err != nil {
			return nil, err
		}
		a.Cfg.AuthMethod = "approle"
		return a, nil
	}
}
