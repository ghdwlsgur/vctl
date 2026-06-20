package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func sshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh [host]",
		Short: "Connect to an inventory host",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, false)
			if err != nil {
				return err
			}
			defer st.Close()

			target, err := pick(ctx, st, args)
			if err != nil {
				return err
			}

			tgt, err := buildTarget(ctx, st, target, a.Cfg.SSHDirectFirst)
			if err != nil {
				return err
			}

			// Capture the most recent Vault-signed cert serial so the access
			// audit row maps to a specific issued certificate. On a jump chain
			// the target is signed last, so this ends up holding its serial.
			var lastSerial string
			sign := func(role, pub string, principals []string, extensions []string) (string, error) {
				cert, err := a.Vault.SignSSH(ctx, role, pub, principals, a.Cfg.SSHSign, extensions)
				if err == nil {
					if s := sshc.CertSerial(cert); s != "" {
						lastSerial = s
					}
				}
				return cert, err
			}

			vaultUser := a.Vault.Identity(ctx)

			ui.Infof(os.Stderr, "connecting to %s (%s@%s)", tgt.Name, tgt.User, tgt.Addr)
			connInfo, connErr := sshc.Connect(ctx, tgt, sign)

			// Best-effort central access log. Never fails the SSH: audit
			// loss is logged to stderr but the connection result is returned as-is.
			entry := accessEntry(vaultUser, tgt, connInfo, lastSerial, connErr)
			if logErr := a.LogAccess(ctx, entry); logErr != nil {
				ui.Warnf(os.Stderr, "access log not recorded: %v", logErr)
			}
			return connErr
		},
	}
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
		TargetAddr: firstNonEmpty(connInfo.TargetAddr, tgt.Addr),
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
		return selectServer(cands, fmt.Sprintf("Select a server matching %q", args[0]))
	}
	// No argument: choose from the full list.
	all, err := st.List(ctx, "")
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("inventory is empty. Run 'vctl sync' first")
	}
	return selectServer(all, "Select a server")
}

// buildTarget converts a server and jump chain into sshc.Target values.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

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
