package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
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
					target, err = resolveServer(ctx, st, server)
				} else {
					target, err = pick(ctx, st, args)
				}
				if err != nil {
					return err
				}

				tgt, err := buildTarget(ctx, st, target, a.Cfg.SSHDirectFirst)
				if err != nil {
					return err
				}
				setHostKeyConfirmation(tgt, server == "")

				sign, certSerial := signAndTrackSerial(ctx, a)

				vaultUser := a.Vault.Identity(ctx)

				ui.Infof(os.Stderr, "connecting to %s (%s@%s)", tgt.Name, tgt.User, tgt.Addr)
				connInfo, connErr := sshc.Connect(ctx, tgt, sign)

				// Best-effort central access log. Never fails the SSH: audit
				// loss is logged to stderr but the connection result is returned as-is.
				entry := accessEntry(vaultUser, tgt, connInfo, certSerial(), connErr)
				if logErr := a.LogAccess(ctx, entry); logErr != nil {
					ui.Warnf(os.Stderr, "access log not recorded: %v", logErr)
				}
				return connErr
			})
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "exact inventory host to connect to (non-interactive; for scripts/agents)")
	return cmd
}

// signAndTrackSerial returns a SignFunc that signs public keys via Vault and a
// getter for the most recent issued cert serial. On a jump chain the target is
// signed last, so the getter ends up holding the target's serial — used to map
// the access-audit row to a specific certificate. Shared by `vctl ssh` and the
// MCP vctl_ssh_exec tool.
func signAndTrackSerial(ctx context.Context, a *app.App) (sshc.SignFunc, func() string) {
	var serial string
	fn := func(role, pub string, principals, extensions []string) (string, error) {
		cert, err := a.Vault.SignSSH(ctx, role, pub, principals, a.Cfg.SSHSign, extensions)
		if err == nil {
			if s := sshc.CertSerial(cert); s != "" {
				serial = s
			}
		}
		return cert, err
	}
	return fn, func() string { return serial }
}

func setHostKeyConfirmation(t *sshc.Target, enabled bool) {
	for t != nil {
		t.ConfirmHostKey = enabled
		t = t.Jump
	}
}

// resolveServer resolves a host non-interactively for --server (scripts/agents):
// exact or unique match only, never a picker. Ambiguous or missing host errors out
// with the candidate list so the caller can pick an exact name.
func resolveServer(ctx context.Context, st *store.Store, query string) (*store.Server, error) {
	sv, cands, err := st.Resolve(ctx, query)
	if err != nil {
		return nil, err
	}
	if sv != nil {
		return sv, nil
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no server matches %q", query)
	}
	names := make([]string, 0, len(cands))
	for _, c := range cands {
		names = append(names, c.Hostname)
	}
	return nil, fmt.Errorf("%q is ambiguous (%d matches: %s) — pass an exact hostname", query, len(cands), strings.Join(names, ", "))
}

func accessEntry(vaultUser string, tgt *sshc.Target, connInfo sshc.ConnectionInfo, certSerial string, connErr error) store.AccessEntry {
	clientUser := ""
	if u, err := user.Current(); err == nil && u != nil {
		clientUser = u.Username
	}
	if clientUser == "" {
		clientUser = os.Getenv("USER")
	}
	clientHost, _ := os.Hostname()
	entry := store.AccessEntry{
		VaultUser:  vaultUser,
		Hostname:   tgt.Name,
		CertSerial: certSerial,
		OK:         connErr == nil,
		SourceIP:   connInfo.SourceIP,
		SourceAddr: connInfo.SourceAddr,
		ClientHost: clientHost,
		ClientUser: clientUser,
		TargetAddr: strutil.FirstNonEmpty(connInfo.TargetAddr, tgt.Addr),
		JumpVia:    connInfo.JumpHost,
	}
	if connErr != nil {
		entry.Error = truncateAuditError(connErr.Error())
	}
	return entry
}

func truncateAuditError(s string) string {
	const max = 500
	if len(s) <= max {
		return s
	}
	return s[:max]
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

// buildTarget converts a server and jump chain into sshc.Target values.
func buildTarget(ctx context.Context, st *store.Store, sv *store.Server, directFirst bool) (*sshc.Target, error) {
	return buildTargetSeen(ctx, st, sv, directFirst, map[string]bool{})
}

func buildTargetSeen(ctx context.Context, st *store.Store, sv *store.Server, directFirst bool, seen map[string]bool) (*sshc.Target, error) {
	if seen[sv.Hostname] {
		return nil, fmt.Errorf("jump host cycle detected: %s", sv.Hostname)
	}
	seen[sv.Hostname] = true

	t := &sshc.Target{
		Name:       sv.Hostname,
		Addr:       net.JoinHostPort(sv.IP, strconv.Itoa(sv.Port)),
		User:       sv.User,
		Role:       sv.CARole,
		SkipDirect: !directFirst,
	}
	if sv.JumpVia != "" {
		jsv, err := st.Get(ctx, sv.JumpVia)
		if err != nil {
			return nil, fmt.Errorf("lookup jump host %q: %w", sv.JumpVia, err)
		}
		jt, err := buildTargetSeen(ctx, st, jsv, directFirst, seen)
		if err != nil {
			return nil, err
		}
		t.Jump = jt
	}
	return t, nil
}
