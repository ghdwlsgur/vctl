package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// addCmd registers a host that `vctl sync` will not discover on its own.
//
// sync reads ~/.ssh/config and probes what it finds there, which covers hosts
// an operator already reaches. It cannot see a machine nobody has an entry for
// yet, and editing ssh config to make the inventory notice a host puts the
// workflow backwards: the central inventory should be able to learn about a
// host directly.
//
// Flags first, form second. Given complete flags this never prompts, so it
// scripts; given none it asks, so nobody has to memorise six flag names. A
// non-interactive caller with incomplete flags gets an error rather than a
// prompt it cannot answer — the failure mode that hangs CI.
//
// Mutate class, and writing the inventory needs a Vault role the baseline user
// policy no longer carries, so this is an operator command by construction
// rather than by convention.
func addCmd(env CommandEnv) *cobra.Command {
	var (
		sv    store.Server
		force bool
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Register an inventory host that sync cannot discover",
		Long: `add registers a host in the central inventory.

Use it for machines that are not in ~/.ssh/config, which is what vctl sync
reads. Run with no flags to fill the fields interactively.

A later sync will not undo this: sync refreshes probe-derived columns only and
leaves ssh_user, dc and jump_via as entered here.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return withStorePort(env, ctx, true, func(_ *app.App, st addStore) error {
				if err := completeServer(ctx, st, &sv); err != nil {
					return err
				}
				if err := validateServer(ctx, st, sv); err != nil {
					return err
				}
				created, err := st.Insert(ctx, sv)
				if err != nil {
					return err
				}
				if !created {
					if !force {
						return fmt.Errorf("%s is already in the inventory; change it with vctl edit, or pass --force to overwrite probe fields", sv.Hostname)
					}
					if err := st.Upsert(ctx, sv); err != nil {
						return err
					}
					ui.Successf(os.Stdout, "updated %s (%s)", sv.Hostname, sv.IP)
					return nil
				}
				addr := sv.IP
				if n := len(sv.ExtraIPs); n > 0 {
					addr = fmt.Sprintf("%s (+%d)", sv.IP, n)
				}
				ui.Successf(os.Stdout, "added %s (%s) in %s", sv.Hostname, addr, sv.DC)
				ui.Infof(os.Stdout, "connect with: vctl ssh %s", sv.Hostname)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&sv.Hostname, "host", "", "inventory hostname (the name vctl ssh takes)")
	f.StringVar(&sv.IP, "ip", "", "address to connect to")
	f.StringVar(&sv.User, "user", "", "SSH login user")
	f.StringVar(&sv.DC, "dc", "", "datacenter label, e.g. seoul-onprem")
	f.StringVar(&sv.JumpVia, "jump", "", "jump host (an existing inventory hostname); empty means direct")
	f.IntVar(&sv.Port, "port", 22, "SSH port")
	f.StringVar(&sv.CARole, "ca-role", "sre-core", "Vault SSH CA role")
	// Repeatable rather than comma-separated. A --extra-ip that swallowed a list
	// would have to define what a bad element does — reject the whole flag, or
	// drop it — and repeating the flag makes each address its own argument that
	// shells complete and quote on their own.
	f.StringSliceVar(&sv.ExtraIPs, "extra-ip", nil, "additional address the host answers on (repeatable)")
	f.BoolVar(&force, "force", false, "if the hostname exists, refresh it instead of failing")
	return gate(cmd, "add")
}

// inventoryLister is the slice of *store.Store that add reads.
//
// The jump-host check and the datacenter suggestions are the parts of this
// command most likely to be wrong, and both were reachable only with a live
// database behind them. Narrowing the dependency to the one method they use
// puts those branches under test; the alternative is trusting the branch that
// decides whether a host is reachable at all.
type inventoryLister interface {
	ListInventory(ctx context.Context, dc string) ([]store.InventoryRow, error)
}

// addStore is what `vctl add` may do to the inventory: read it to validate
// the new host, and write that one host. The command used to receive the
// whole store, with every other write along for the ride.
type addStore interface {
	inventoryLister
	Insert(ctx context.Context, sv store.Server) (bool, error)
	Upsert(ctx context.Context, sv store.Server) error
}

var _ addStore = (*store.Store)(nil)

// completeServer fills whatever the flags left empty, asking only when there is
// a terminal to ask at.
func completeServer(ctx context.Context, st inventoryLister, sv *store.Server) error {
	if sv.Hostname != "" && sv.IP != "" && sv.User != "" && sv.DC != "" {
		return nil
	}
	if !isTerminal() {
		return fmt.Errorf("--host, --ip, --user and --dc are required when there is no terminal to prompt at")
	}

	// Offer the labels already in use. A free-text datacenter is how an
	// inventory ends up with "seoul-onprem", "seoul_onprem" and "Seoul" as three
	// places, and grouped listings then show the same site three times.
	dcs := knownDCs(ctx, st)
	extraIPs := strings.Join(sv.ExtraIPs, ", ")

	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Hostname").
			Description("the name `vctl ssh` will take").
			Value(&sv.Hostname).
			Validate(nonEmpty("hostname")),
		huh.NewInput().Title("Address").
			Description("IP to connect to").
			Value(&sv.IP).
			Validate(func(s string) error {
				if net.ParseIP(strings.TrimSpace(s)) == nil {
					return fmt.Errorf("not an IP address")
				}
				return nil
			}),
		huh.NewInput().Title("SSH user").Value(&sv.User).Validate(nonEmpty("user")),
		dcField(dcs, &sv.DC),
		huh.NewInput().Title("Jump host").
			Description("leave empty for a direct connection").
			Value(&sv.JumpVia),
		// One line, comma separated: a form cannot repeat a field the way a flag
		// repeats, and asking "another address? y/n" in a loop is worse than
		// letting someone paste what they already have.
		huh.NewInput().Title("Other addresses").
			Description("comma separated; VIPs or extra NICs. leave empty if none").
			Value(&extraIPs).
			Validate(func(s string) error {
				for _, e := range splitIPList(s) {
					if net.ParseIP(e) == nil {
						return fmt.Errorf("%q is not an IP address", e)
					}
				}
				return nil
			}),
	))
	if err := form.WithTheme(ui.FormTheme()).WithKeyMap(ui.FormKeyMap()).Run(); err != nil {
		return err
	}
	sv.Hostname = strings.TrimSpace(sv.Hostname)
	sv.IP = strings.TrimSpace(sv.IP)
	sv.User = strings.TrimSpace(sv.User)
	sv.DC = strings.TrimSpace(sv.DC)
	sv.JumpVia = strings.TrimSpace(sv.JumpVia)
	sv.ExtraIPs = splitIPList(extraIPs)
	return nil
}

// splitIPList reads the comma separated form field. Blank entries are dropped
// rather than becoming empty addresses, because a trailing comma is what a
// pasted list usually ends with.
func splitIPList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dcField offers the existing labels when there are any, and falls back to free
// text on a fresh inventory where there is nothing to choose from yet.
func dcField(dcs []string, target *string) huh.Field {
	if len(dcs) == 0 {
		return huh.NewInput().Title("Datacenter").Value(target).Validate(nonEmpty("datacenter"))
	}
	opts := make([]huh.Option[string], 0, len(dcs))
	for _, dc := range dcs {
		opts = append(opts, huh.NewOption(dc, dc))
	}
	return huh.NewSelect[string]().
		Title("Datacenter").
		Description("labels already in the inventory").
		Options(opts...).
		Value(target).
		// Inline for the same reason as the State fields: a list select would
		// swallow ↑/↓ and leave no obvious way back to the previous field.
		Inline(true)
}

func nonEmpty(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", what)
		}
		return nil
	}
}

// knownDCs returns the datacenter labels already in use, best effort: the form
// is still usable without them.
func knownDCs(ctx context.Context, st inventoryLister) []string {
	if st == nil {
		return nil
	}
	rows, err := st.ListInventory(ctx, "")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		if r.DC == "" || seen[r.DC] {
			continue
		}
		seen[r.DC] = true
		out = append(out, r.DC)
	}
	return out
}

// validateServer rejects what the database would accept but `vctl ssh` could
// not use. A row that parses is not the same as a host anyone can reach.
func validateServer(ctx context.Context, st inventoryLister, sv store.Server) error {
	if strings.TrimSpace(sv.Hostname) == "" {
		return fmt.Errorf("--host is required")
	}
	if net.ParseIP(sv.IP) == nil {
		return fmt.Errorf("invalid --ip: %q", sv.IP)
	}
	if strings.TrimSpace(sv.User) == "" {
		return fmt.Errorf("--user is required")
	}
	if strings.TrimSpace(sv.DC) == "" {
		return fmt.Errorf("--dc is required")
	}
	if sv.Port <= 0 || sv.Port > 65535 {
		return fmt.Errorf("invalid --port: %d", sv.Port)
	}
	// Extra addresses are what `vctl ssh --server <ip>` matches on, and what the
	// WireGuard view resolves endpoints through. An unparseable one is stored as
	// an inet[] element by Postgres or rejected outright depending on the value,
	// so it is checked here where the operator can still fix the typo.
	for _, e := range sv.ExtraIPs {
		if net.ParseIP(strings.TrimSpace(e)) == nil {
			return fmt.Errorf("invalid --extra-ip: %q", e)
		}
		if strings.TrimSpace(e) == sv.IP {
			return fmt.Errorf("--extra-ip %q repeats --ip", e)
		}
	}
	if sv.JumpVia == "" {
		return nil
	}
	// A jump host that is not in the inventory produces a row that looks fine
	// and fails at connect time, when the operator is no longer thinking about
	// the add. Catching it here costs one query.
	if sv.JumpVia == sv.Hostname {
		return fmt.Errorf("--jump points at the host itself")
	}
	if st == nil {
		return nil
	}
	rows, err := st.ListInventory(ctx, "")
	if err != nil {
		// The jump check is a courtesy. Failing the add because the lookup that
		// would have helped is unavailable trades a real problem for a possible
		// one.
		return nil
	}
	for _, r := range rows {
		if r.Hostname == sv.JumpVia {
			return nil
		}
	}
	return fmt.Errorf("jump host %q is not in the inventory", sv.JumpVia)
}
