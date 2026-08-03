package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

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
func addCmd() *cobra.Command {
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
			return withStore(ctx, true, func(_ *app.App, st *store.Store) error {
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
						return fmt.Errorf("%s is already in the inventory; edit it with vctl ip / dbedit, or pass --force to overwrite probe fields", sv.Hostname)
					}
					if err := st.Upsert(ctx, sv); err != nil {
						return err
					}
					ui.Successf(os.Stdout, "updated %s (%s)", sv.Hostname, sv.IP)
					return nil
				}
				ui.Successf(os.Stdout, "added %s (%s) in %s", sv.Hostname, sv.IP, sv.DC)
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
	f.BoolVar(&force, "force", false, "if the hostname exists, refresh it instead of failing")
	return gate(cmd, "add", classMutate)
}

// completeServer fills whatever the flags left empty, asking only when there is
// a terminal to ask at.
func completeServer(ctx context.Context, st *store.Store, sv *store.Server) error {
	if sv.Hostname != "" && sv.IP != "" && sv.User != "" && sv.DC != "" {
		return nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("--host, --ip, --user and --dc are required when there is no terminal to prompt at")
	}

	// Offer the labels already in use. A free-text datacenter is how an
	// inventory ends up with "seoul-onprem", "seoul_onprem" and "Seoul" as three
	// places, and grouped listings then show the same site three times.
	dcs := knownDCs(ctx, st)

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
	))
	if err := form.Run(); err != nil {
		return err
	}
	sv.Hostname = strings.TrimSpace(sv.Hostname)
	sv.IP = strings.TrimSpace(sv.IP)
	sv.User = strings.TrimSpace(sv.User)
	sv.DC = strings.TrimSpace(sv.DC)
	sv.JumpVia = strings.TrimSpace(sv.JumpVia)
	return nil
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
		Value(target)
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
func knownDCs(ctx context.Context, st *store.Store) []string {
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
func validateServer(ctx context.Context, st *store.Store, sv store.Server) error {
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
	if sv.JumpVia == "" {
		return nil
	}
	// A jump host that is not in the inventory produces a row that looks fine
	// and fails at connect time, when the operator is no longer thinking about
	// the add. Catching it here costs one query.
	if sv.JumpVia == sv.Hostname {
		return fmt.Errorf("--jump points at the host itself")
	}
	rows, err := st.ListInventory(ctx, "")
	if err != nil {
		return nil // the jump check is a courtesy; do not fail the add on it
	}
	for _, r := range rows {
		if r.Hostname == sv.JumpVia {
			return nil
		}
	}
	return fmt.Errorf("jump host %q is not in the inventory", sv.JumpVia)
}
