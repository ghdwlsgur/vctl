package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/invcache"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func sshCmd(env CommandEnv) *cobra.Command {
	var server, vm, user, vmFarm string
	var allowStale bool
	cmd := &cobra.Command{
		Use:   "ssh [host|user@addr]",
		Short: "Connect to an inventory host, or to an address directly",
		Long: `Connect to an inventory host.

Interactive:  vctl ssh [host]            fuzzy match; picker when ambiguous/omitted
Non-interactive (scripts/agents):
              vctl ssh --server <host>   exact/unique match only; errors instead of prompting

Direct:       vctl ssh ubuntu@192.0.2.10        an address, not an inventory name
              vctl ssh ubuntu@192.0.2.10:2222

VM:           vctl ssh --vm <nova-uuid> --user rocky
              vctl ssh --vm openstack:///<nova-uuid> --user rocky

A VM is addressed by its Nova id only — a name can fit several VMs across farms,
and resolving that by position would connect to whichever sorted first. The
address is the one the VM listing shows. --user says who to log in as: Nova does
not record one, so it falls back to the configured default and the connection
line names whoever that turned out to be.

A direct target skips inventory entirely, so it reaches a host that was never
registered — as long as the host already trusts the Vault SSH CA (see
'vctl trust-ca'). The certificate, the RBAC gate and the access-log row are the
same as for any other connection; what inventory would have supplied is not:
there is no jump chain (direct connection only) and the CA role falls back to
the configured default.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if server != "" && len(args) > 0 {
				return fmt.Errorf("pass the host via --server or as a positional argument, not both")
			}
			if vm != "" && (server != "" || len(args) > 0) {
				return fmt.Errorf("pass a VM via --vm, or a host, not both")
			}
			// --user is the VM path's flag. On a host the login comes from the
			// inventory, and on user@addr it is already in the argument, so a
			// --user there is silently doing nothing.
			if vm == "" && cmd.Flags().Changed("user") {
				return fmt.Errorf("--user goes with --vm; a host's login user comes from the inventory, and a direct target carries it in user@addr")
			}
			if vm != "" {
				return sshVM(ctx, env, vm, user, vmFarm, allowStale)
			}
			query := server
			if query == "" && len(args) > 0 {
				query = args[0]
			}

			// A terminal session may confirm an unknown host key; --server is
			// non-interactive (scripts/agents) so it is strict instead.
			policy := access.HostKeyPrompt
			if server != "" {
				policy = access.HostKeyStrict
			}

			// A direct address needs nothing from the inventory, so it does not
			// open it. That also makes this the way in when the inventory
			// database itself is unreachable and the snapshot cannot help.
			if ep, ok := parseUserAtAddr(query); ok {
				return env.withApp(func(a *app.App) error {
					tgt := ep.target(a.Cfg)
					ui.Infof(os.Stderr, "connecting to %s@%s (direct, not from inventory)", tgt.User, tgt.Addr)
					return newConnector(a).Connect(ctx, access.Request{Target: tgt, HostKey: policy})
				})
			}

			return env.withInventory(ctx, func(a *app.App, inv *app.Inventory) error {
				var (
					target *store.Server
					err    error
				)
				if server != "" {
					target, err = access.ResolveServer(ctx, inv, server)
				} else {
					target, err = pick(ctx, inv, args)
				}
				if err != nil {
					return err
				}

				tgt, err := access.BuildTarget(ctx, inv, target, a.Cfg.SSHDirectFirst)
				if err != nil {
					return err
				}

				ui.Infof(os.Stderr, "connecting to %s (%s@%s)", tgt.Name, tgt.User, tgt.Addr)
				return newConnector(a).Connect(ctx, access.Request{Target: tgt, HostKey: policy})
			})
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "exact inventory host, or user@addr, to connect to (non-interactive; for scripts/agents)")
	cmd.Flags().StringVar(&vm, "vm", "", "a Nova instance id, or a Kubernetes providerID (openstack:///<uuid>)")
	cmd.Flags().StringVar(&user, "user", "", "login user for --vm (Nova does not record one)")
	cmd.Flags().BoolVar(&allowStale, "allow-stale", false, "connect to a --vm whose record is older than the collector's schedule")
	cmd.Flags().StringVar(&vmFarm, "farm", "", "deployment holding the --vm instance, when its id is in more than one")
	registerCompletion(cmd, "server", completeInventoryHost(env))
	registerCompletion(cmd, "vm", completeVM(env))
	registerCompletion(cmd, "farm", completeFarm(env))
	// The positional takes an inventory name or user@addr, and only the first
	// of those is something anything here knows. The direct form needs no
	// inventory, which is the point of it.
	cmd.ValidArgsFunction = completeInventoryHost(env)
	return cmd
}

// sshEndpoint is a target given as an address on the command line instead of a
// name to look up.
type sshEndpoint struct {
	User string
	Host string
	Port string
}

// parseUserAtAddr splits "user@host", "user@host:port" or "user@[v6]:port".
// ok is false when there is no "@", which is how callers tell a direct address
// from an inventory name — an inventory hostname never contains one.
func parseUserAtAddr(arg string) (sshEndpoint, bool) {
	at := strings.Index(arg, "@")
	if at <= 0 || at == len(arg)-1 {
		return sshEndpoint{}, false
	}
	ep := sshEndpoint{User: arg[:at], Host: arg[at+1:], Port: "22"}
	if h, p, err := net.SplitHostPort(ep.Host); err == nil {
		ep.Host, ep.Port = h, p
	}
	return ep, true
}

// target builds the connection for a direct address. There is no jump chain: a
// jump host is inventory topology, and this path deliberately has no inventory.
// SkipDirect stays false for the same reason — direct is the only route.
func (e sshEndpoint) target(cfg *config.Config) *sshc.Target {
	user := e.User
	if user == "" {
		user = cfg.SSHDefaultUser
	}
	return &sshc.Target{
		Name: e.Host,
		Addr: net.JoinHostPort(e.Host, e.Port),
		User: user,
		Role: cfg.CARole,
	}
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
			ui.Warnf(os.Stderr, "%s", auditErrorMessage(err))
		},
	}
}

// auditErrorMessage turns a failed audit write into what the operator needs to
// know: whether the record is gone or merely waiting.
//
// The distinction is the whole point of the spool. Reporting a queued record as
// "not recorded" would tell someone their access left no trace at the exact
// moment it did — and would push them to go re-record it by hand.
func auditErrorMessage(err error) string {
	var spooled *app.SpooledError
	if errors.As(err, &spooled) {
		return fmt.Sprintf("audit database unreachable — access record queued locally (%d pending), "+
			"it flushes on the next successful write", spooled.Pending)
	}
	return fmt.Sprintf("access log not recorded: %v", err)
}

// pick selects one server by argument, fuzzy match, or interactive picker. It
// takes the inventory handle rather than the store so the picker works the same
// against a cached inventory — and knows to say so.
func pick(ctx context.Context, inv *app.Inventory, args []string) (*store.Server, error) {
	if len(args) == 1 {
		sv, cands, err := inv.Resolve(ctx, args[0])
		if err != nil {
			return nil, err
		}
		if sv != nil {
			return sv, nil
		}
		if len(cands) == 0 {
			return nil, fmt.Errorf("no server matches %q", args[0])
		}
		ws, err := withLiveStatus(ctx, inv, cands)
		if err != nil {
			return nil, err
		}
		sel, err := selectServer(ws, fmt.Sprintf("Select a server matching %q", args[0]), inv.Cached())
		if err != nil {
			return nil, err
		}
		return &sel.Server, nil
	}
	// No argument: choose from the full list (with live agent status).
	all, err := inv.ListWithStatus(ctx, "")
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("inventory is empty. Run 'vctl sync' first")
	}
	sel, err := selectServer(all, "Select a server", inv.Cached())
	if err != nil {
		return nil, err
	}
	return &sel.Server, nil
}

// withLiveStatus pairs resolved candidates with their runtime status (agent
// freshness / probe) so the picker shows the same up/down as `vctl list`.
func withLiveStatus(ctx context.Context, st invcache.Reader, cands []store.Server) ([]store.ServerWithStatus, error) {
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

// sshVM connects to a Nova instance.
//
// Exact identity only. A VM name fits several VMs across farms — this fleet has
// two called secloudit-pkg-bastion in different deployments — and resolving that
// by position would connect to whichever sorted first, which is the kind of
// mistake nothing downstream can catch. The id is what kubectl prints, what
// `vctl openstack vm` prints, and what a person is likely to have.
//
// Host key policy follows whether somebody is present, not the flag's shape.
//
// Strict was the first choice, on the reasoning that an identifier is what
// scripts use. Running it showed why that cannot stand alone: the refusal reads
// "connect interactively once to verify it", and there is no interactive way to
// reach a VM — --vm is the only door. Every first connection was a dead end.
//
// A physical host has both doors: the positional form prompts, --server does
// not. Here the terminal is what says which one this is.
func sshVM(ctx context.Context, env CommandEnv, selector, user, farm string, allowStale bool) error {
	id, ok := access.NovaID(selector)
	if !ok {
		return fmt.Errorf("--vm takes a Nova instance id or openstack:///<id>, not %q; "+
			"run 'vctl openstack vm' to find it", selector)
	}
	return env.withStore(ctx, false, func(a *app.App, st *store.Store) error {
		deployment := ""
		if farm != "" {
			resolved, err := resolveFarmID(ctx, a, st, farm)
			if err != nil {
				return err
			}
			deployment = resolved
		}
		v, err := oneVM(ctx, st, id, deployment)
		if err != nil {
			return err
		}
		if v.MissingSince != nil {
			// The control plane stopped listing it. Connecting anyway would be
			// reaching for an address that belonged to something else by now.
			return fmt.Errorf("%s (%s) is no longer listed by its control plane", v.Name, id)
		}
		// An address is only as current as the pass that recorded it.
		//
		// MissingSince alone was the whole check, and it only says the control
		// plane answered and left this VM out. A reconcile that has been failing
		// for days sets nothing: the rows keep their addresses, look exactly
		// like fresh ones, and the address in them is where some VM used to be.
		// On a tenant range that gets reused, that is somebody else's machine.
		if age := time.Since(v.ObservedAt); age > vmStaleWindow && !allowStale {
			when := "never collected"
			if !v.ObservedAt.IsZero() {
				when = strutil.CompactDuration(age) + " ago"
			}
			if !isTerminal() {
				return fmt.Errorf("%s was last collected %s, older than the collector's schedule; "+
					"run 'vctl openstack reconcile' or pass --allow-stale", nameOrID(v), when)
			}
			ui.Warnf(os.Stderr, "%s in %s was last collected %s — its address may not be current",
				nameOrID(v), v.DeploymentID, when)
			var ok bool
			if err := huh.NewForm(huh.NewGroup(
				huh.NewConfirm().
					Title("Connect to " + nameOrID(v) + " on a stale record?").
					Description(fmt.Sprintf("%s in %s, last collected %s", id, v.DeploymentID, when)).
					Affirmative("Connect").
					Negative("Cancel").
					Value(&ok),
			)).WithTheme(ui.FormTheme()).WithKeyMap(ui.FormKeyMap()).Run(); err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("not connecting to a stale record")
			}
		}
		if user == "" {
			user = a.Cfg.SSHDefaultUser
		}
		tgt, err := access.VMTarget(v.Name, v.Addresses, access.VMPolicy{
			User: user, CARole: a.Cfg.CARole, OperatorNets: a.Cfg.OperatorNetworks,
		})
		if err != nil {
			return err
		}
		ui.Infof(os.Stderr, "connecting to %s (%s@%s) — VM in %s, project %s",
			tgt.Name, tgt.User, tgt.Addr, v.DeploymentID, orUnknown(v.ProjectName))
		policy := access.HostKeyStrict
		if isTerminal() {
			policy = access.HostKeyPrompt
		}
		return newConnector(a).Connect(ctx, access.Request{Target: tgt, HostKey: policy})
	})
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
