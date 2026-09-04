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
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/cli/openstack"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/invcache"
	osdomain "github.com/ghdwlsgur/vctl/internal/openstack"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func sshCmd(env cmdkit.Env) *cobra.Command {
	var opts sshOptions
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
			return runSSH(cmd, env, args, opts)
		},
	}
	cmd.Flags().StringVar(&opts.server, "server", "", "exact inventory host, or user@addr, to connect to (non-interactive; for scripts/agents)")
	cmd.Flags().StringVar(&opts.vm, "vm", "", "a Nova instance id, or a Kubernetes providerID (openstack:///<uuid>)")
	cmd.Flags().StringVar(&opts.user, "user", "", "login user for --vm (Nova does not record one)")
	cmd.Flags().BoolVar(&opts.allowStale, "allow-stale", false, "connect to a --vm whose record is older than the collector's schedule")
	cmd.Flags().StringVar(&opts.vmFarm, "farm", "", "deployment holding the --vm instance, when its id is in more than one")
	cmdkit.RegisterCompletion(cmd, "server", cmdkit.CompleteInventoryHost(env))
	cmdkit.RegisterCompletion(cmd, "vm", openstack.CompleteVM(env))
	cmdkit.RegisterCompletion(cmd, "farm", openstack.CompleteFarm(env))
	// The positional takes an inventory name or user@addr, and only the first
	// of those is something anything here knows. The direct form needs no
	// inventory, which is the point of it.
	cmd.ValidArgsFunction = cmdkit.CompleteInventoryHost(env)
	return cmd
}

type sshOptions struct {
	server, vm, user, vmFarm string
	allowStale               bool
}

// runSSH validates the flag/argument combination, then hands off to the VM
// path, the direct user@addr path, or the inventory path.
func runSSH(cmd *cobra.Command, env cmdkit.Env, args []string, opts sshOptions) error {
	ctx := cmd.Context()
	if opts.server != "" && len(args) > 0 {
		return fmt.Errorf("pass the host via --server or as a positional argument, not both")
	}
	if opts.vm != "" && (opts.server != "" || len(args) > 0) {
		return fmt.Errorf("pass a VM via --vm, or a host, not both")
	}
	// --user is the VM path's flag. On a host the login comes from the
	// inventory, and on user@addr it is already in the argument, so a
	// --user there is silently doing nothing.
	if opts.vm == "" && cmd.Flags().Changed("user") {
		return fmt.Errorf("--user goes with --vm; a host's login user comes from the inventory, and a direct target carries it in user@addr")
	}
	if opts.vm != "" {
		return sshVM(ctx, env, opts.vm, opts.user, opts.vmFarm, opts.allowStale)
	}
	query := opts.server
	if query == "" && len(args) > 0 {
		query = args[0]
	}

	// A terminal session may confirm an unknown host key; --server is
	// non-interactive (scripts/agents) so it is strict instead.
	policy := access.HostKeyPrompt
	if opts.server != "" {
		policy = access.HostKeyStrict
	}

	// A direct address needs nothing from the inventory, so it does not
	// open it. That also makes this the way in when the inventory
	// database itself is unreachable and the snapshot cannot help.
	if ep, ok := parseUserAtAddr(query); ok {
		return env.WithApp(func(a *app.App) error {
			tgt := ep.target(a.Cfg)
			ui.Infof(os.Stderr, "connecting to %s@%s (direct, not from inventory)", tgt.User, tgt.Addr)
			return cmdkit.NewConnector(a).Connect(ctx, access.Request{Target: tgt, HostKey: policy})
		})
	}

	return env.WithInventory(ctx, func(a *app.App, inv *app.Inventory) error {
		var (
			target *store.Server
			err    error
		)
		if opts.server != "" {
			target, err = access.ResolveServer(ctx, inv, opts.server)
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
		return cmdkit.NewConnector(a).Connect(ctx, access.Request{Target: tgt, HostKey: policy})
	})
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

// sshVM connects to a Nova instance, in phases that each answer one question:
// which VM the selector means, whether its record is current enough to dial,
// and how to reach it as some login user. Each phase is its own function so
// the reasoning that belongs to it stays beside it.
//
// Exact identity only. A VM name fits several VMs across farms — this fleet has
// two called secloudit-pkg-bastion in different deployments — and resolving that
// by position would connect to whichever sorted first, which is the kind of
// mistake nothing downstream can catch. The id is what kubectl prints, what
// `vctl openstack vm` prints, and what a person is likely to have.
func sshVM(ctx context.Context, env cmdkit.Env, selector, user, farm string, allowStale bool) error {
	id, ok := access.NovaID(selector)
	if !ok {
		return fmt.Errorf("--vm takes a Nova instance id or openstack:///<id>, not %q; "+
			"run 'vctl openstack vm' to find it", selector)
	}
	return env.WithStore(ctx, false, func(a *app.App, st *store.Store) error {
		v, err := lookupVM(ctx, a, st, id, farm)
		if err != nil {
			return err
		}
		if err := checkVMCurrent(v, id, allowStale); err != nil {
			return err
		}
		return connectVM(ctx, a, st, v, user)
	})
}

// lookupVM finds the instance the id names — within one deployment when a
// farm was given, since the same id can sit in more than one.
func lookupVM(ctx context.Context, a *app.App, st *store.Store, id, farm string) (store.Instance, error) {
	deployment := ""
	if farm != "" {
		resolved, err := openstack.ResolveFarmID(ctx, a, st, farm)
		if err != nil {
			return store.Instance{}, err
		}
		deployment = resolved
	}
	return openstack.OneVM(ctx, st, id, deployment)
}

// checkVMCurrent refuses a record the control plane no longer lists, and one
// older than the collector's schedule unless --allow-stale was passed or the
// person at the terminal confirms it.
func checkVMCurrent(v store.Instance, id string, allowStale bool) error {
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
	if age := time.Since(v.ObservedAt); age > openstack.StaleProbeWindow && !allowStale {
		when := "never collected"
		if !v.ObservedAt.IsZero() {
			when = strutil.CompactDuration(age) + " ago"
		}
		if !cmdkit.IsTerminal() {
			return fmt.Errorf("%s was last collected %s, older than the collector's schedule; "+
				"run 'vctl openstack reconcile' or pass --allow-stale", openstack.NameOrID(v), when)
		}
		ui.Warnf(os.Stderr, "%s in %s was last collected %s — its address may not be current",
			openstack.NameOrID(v), v.DeploymentID, when)
		var ok bool
		if err := huh.NewForm(huh.NewGroup(
			huh.NewConfirm().
				Title("Connect to " + openstack.NameOrID(v) + " on a stale record?").
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
	return nil
}

// vmTarget is how to reach the VM as one login user: its vouched address when
// it has one, otherwise a hop through a same-project sibling that does.
func vmTarget(ctx context.Context, a *app.App, st *store.Store, v store.Instance, u string) (*sshc.Target, error) {
	policyIn := access.VMPolicy{
		User: u, CARole: a.Cfg.CARole, OperatorNets: a.Cfg.OperatorNetworks,
	}
	tgt, err := access.VMTarget(v.Name, v.Addresses, policyIn)
	if err == nil {
		return tgt, nil
	}
	// Tenant-only is not always the end: a same-project sibling holding
	// a port on the same tenant network is a hop this data does vouch
	// for. The read is the database, never the stored reading — the
	// sibling's address is about to be dialed.
	if !errors.Is(err, access.ErrNoVouchedAddress) {
		return nil, err
	}
	siblings, serr := st.Instances(ctx, store.InstanceFilter{
		DeploymentID: v.DeploymentID, ProjectIDs: []string{v.ProjectID},
	})
	if serr != nil {
		// Still the primary condition (callers match on it), but the reason
		// the jump search stopped is the store, and saying so is the difference
		// between "add a floating IP" and "the database is down".
		return nil, fmt.Errorf("%w — and the search for a jump host failed: %v", err, serr)
	}
	via, viaAddr, tenantAddr, ok := osdomain.TenantJump(v, siblings, a.Cfg.OperatorNetworks)
	if !ok {
		return nil, fmt.Errorf("%w — and no ACTIVE VM on its tenant network carries one to jump through", err)
	}
	ui.Infof(os.Stderr, "%s is tenant-only — dialing %s directly, falling back through %s (%s)",
		openstack.NameOrID(v), tenantAddr, openstack.NameOrID(*via), viaAddr)
	return access.VMTargetVia(v.Name, tenantAddr, openstack.NameOrID(*via), viaAddr, policyIn), nil
}

// connectVM walks the login candidates for the VM and connects as the first
// one it accepts.
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
func connectVM(ctx context.Context, a *app.App, st *store.Store, v store.Instance, user string) error {
	// A named user is exact; an unnamed one is a walk — root first, then
	// what the image name implies, then the configured default. Only an
	// authentication refusal advances it: a route that is down answers the
	// same for every user.
	cands := []string{user}
	if user == "" {
		cands = osdomain.LoginCandidates(v.ImageName, a.Cfg.SSHDefaultUser)
	}
	policy := access.HostKeyStrict
	if cmdkit.IsTerminal() {
		policy = access.HostKeyPrompt
	}
	_, err := access.TryLoginUsers(cands, func(u string) error {
		tgt, terr := vmTarget(ctx, a, st, v, u)
		if terr != nil {
			return terr
		}
		ui.Infof(os.Stderr, "connecting to %s (%s@%s) — VM in %s, project %s",
			tgt.Name, tgt.User, tgt.Addr, v.DeploymentID, orUnknown(v.ProjectName))
		return cmdkit.NewConnector(a).Connect(ctx, access.Request{Target: tgt, HostKey: policy})
	}, func(rejectedUser, next string) {
		ui.Warnf(os.Stderr, "%s rejected login user %q — trying %q (image %s)",
			openstack.NameOrID(v), rejectedUser, next, orUnknown(v.ImageName))
	})
	return err
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
