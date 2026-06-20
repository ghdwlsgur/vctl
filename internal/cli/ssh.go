package cli

import (
	"context"
	"fmt"
	"net"
	"os"
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

			tgt, err := buildTarget(ctx, st, target)
			if err != nil {
				return err
			}

			sign := func(role, pub string, principals []string, extensions []string) (string, error) {
				return a.Vault.SignSSH(ctx, role, pub, principals, a.Cfg.SSHSign, extensions)
			}

			ui.Infof(os.Stderr, "connecting to %s (%s@%s)", tgt.Name, tgt.User, tgt.Addr)
			return sshc.Connect(ctx, tgt, sign)
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
func buildTarget(ctx context.Context, st *store.Store, sv *store.Server) (*sshc.Target, error) {
	return buildTargetSeen(ctx, st, sv, map[string]bool{})
}

func buildTargetSeen(ctx context.Context, st *store.Store, sv *store.Server, seen map[string]bool) (*sshc.Target, error) {
	if seen[sv.Hostname] {
		return nil, fmt.Errorf("jump host cycle detected: %s", sv.Hostname)
	}
	seen[sv.Hostname] = true

	t := &sshc.Target{
		Name: sv.Hostname,
		Addr: net.JoinHostPort(sv.IP, strconv.Itoa(sv.Port)),
		User: sv.User,
		Role: sv.CARole,
	}
	if sv.JumpVia != "" {
		jsv, err := st.Get(ctx, sv.JumpVia)
		if err != nil {
			return nil, fmt.Errorf("lookup jump host %q: %w", sv.JumpVia, err)
		}
		jt, err := buildTargetSeen(ctx, st, jsv, seen)
		if err != nil {
			return nil, err
		}
		t.Jump = jt
	}
	return t, nil
}
