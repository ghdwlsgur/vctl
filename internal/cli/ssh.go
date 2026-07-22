package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func sshCmd() *cobra.Command {
	var server string
	cmd := &cobra.Command{
		Use:   "ssh [host]",
		Short: "Connect to an inventory host",
		Long: `Connect to an inventory host.

Interactive:  vctl ssh [host]            fuzzy match; picker when ambiguous/omitted
Non-interactive (scripts/agents):
              vctl ssh --server <host>   exact/unique match only; errors instead of prompting`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return withStore(ctx, false, func(a *app.App, st *store.Store) error {
				var (
					target *store.Server
					err    error
				)
				if server != "" {
					if len(args) > 0 {
						return fmt.Errorf("pass the host via --server or as a positional argument, not both")
					}
					target, err = access.ResolveServer(ctx, st, server)
				} else {
					target, err = pick(ctx, st, args)
				}
				if err != nil {
					return err
				}

				tgt, err := access.BuildTarget(ctx, st, target, a.Cfg.SSHDirectFirst)
				if err != nil {
					return err
				}

				// A terminal session may confirm an unknown host key; --server is
				// non-interactive (scripts/agents) so it is strict instead.
				policy := access.HostKeyPrompt
				if server != "" {
					policy = access.HostKeyStrict
				}

				ui.Infof(os.Stderr, "connecting to %s (%s@%s)", tgt.Name, tgt.User, tgt.Addr)
				return newConnector(a).Connect(ctx, access.Request{Target: tgt, HostKey: policy})
			})
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "exact inventory host to connect to (non-interactive; for scripts/agents)")
	return cmd
}

// newConnector builds the SSH connector for this app: Vault signs certs and
// reports the identity, the app writes the audit row, and an audit-write failure
// is warned (never fatal). Shared by `vctl ssh` and the MCP vctl_ssh_exec tool.
func newConnector(a *app.App) *access.Connector {
	return &access.Connector{
		Signer:   a.Vault,
		Identity: a.Vault,
		Audit:    a,
		SignTTL:  a.Cfg.SSHSign,
		OnAuditError: func(err error) {
			ui.Warnf(os.Stderr, "access log not recorded: %v", err)
		},
	}
}

// pick selects one server by argument, fuzzy match, or interactive picker.
func pick(ctx context.Context, st *store.Store, args []string) (*store.Server, error) {
	if len(args) == 1 {
		sv, cands, err := st.Resolve(ctx, args[0])
		if err != nil {
			return nil, err
		}
		if sv != nil {
			return sv, nil
		}
		if len(cands) == 0 {
			return nil, fmt.Errorf("no server matches %q", args[0])
		}
		ws, err := withLiveStatus(ctx, st, cands)
		if err != nil {
			return nil, err
		}
		sel, err := selectServer(ws, fmt.Sprintf("Select a server matching %q", args[0]))
		if err != nil {
			return nil, err
		}
		return &sel.Server, nil
	}
	// No argument: choose from the full list (with live agent status).
	all, err := st.ListWithStatus(ctx, "")
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("inventory is empty. Run 'vctl sync' first")
	}
	sel, err := selectServer(all, "Select a server")
	if err != nil {
		return nil, err
	}
	return &sel.Server, nil
}

// withLiveStatus pairs resolved candidates with their runtime status (agent
// freshness / probe) so the picker shows the same up/down as `vctl list`.
func withLiveStatus(ctx context.Context, st *store.Store, cands []store.Server) ([]store.ServerWithStatus, error) {
	withStatus, err := st.ListWithStatus(ctx, "")
	if err != nil {
		return nil, err
	}
	byHost := make(map[string]store.ServerWithStatus, len(withStatus))
	for _, w := range withStatus {
		byHost[w.Hostname] = w
	}
	out := make([]store.ServerWithStatus, len(cands))
	for i, c := range cands {
		if w, ok := byHost[c.Hostname]; ok {
			out[i] = w
		} else {
			out[i] = store.ServerWithStatus{Server: c}
		}
	}
	return out, nil
}
