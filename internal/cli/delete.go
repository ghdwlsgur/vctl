package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// deleteCmd removes a decommissioned host from the inventory.
//
// Audit rows keyed by the hostname stay. They are the record of what was done
// on that machine while it existed, and deleting the host does not make that
// history untrue — losing it because a VM was torn down would be the audit
// trail failing at exactly the moment it matters.
//
// What does not stay is any jump chain pointing at this host, and that is why
// the command refuses rather than cascades: silently rewriting other hosts to
// "direct" would leave them unreachable with no sign of why.
func deleteCmd(env CommandEnv) *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:     "delete [hostname]",
		Aliases: []string{"rm"},
		Short:   "Remove a decommissioned host from the inventory",
		Long: `delete removes a host from the inventory.

Run with no hostname to pick one from the inventory.

Audit history keyed by the hostname is kept: it records what happened while the
host existed. Hosts that jump through this one block the delete, because
repointing them silently would leave them unreachable.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return env.withStore(ctx, true, func(_ *app.App, st *store.Store) error {
				cur, err := resolveHost(ctx, st, args, "Delete which host?")
				if err != nil {
					return err
				}
				host := cur.Hostname
				dependents, err := jumpDependents(ctx, st, host)
				if err != nil {
					return err
				}
				if len(dependents) > 0 {
					return fmt.Errorf("%s is the jump host for %s; repoint them first (vctl edit <host> --jump ...)",
						host, strings.Join(dependents, ", "))
				}
				if !yes {
					ok, err := confirmDelete(cur)
					if err != nil {
						return err
					}
					if !ok {
						ui.Infof(os.Stdout, "cancelled")
						return nil
					}
				}
				removed, err := st.Delete(ctx, host)
				if err != nil {
					return err
				}
				if !removed {
					return fmt.Errorf("no host named %q", host)
				}
				ui.Successf(os.Stdout, "removed %s (%s)", host, cur.IP)
				ui.Infof(os.Stdout, "audit history for this hostname is kept")
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt")
	return gate(cmd, "delete")
}

// jumpDependents lists the hosts that reach the network through this one.
func jumpDependents(ctx context.Context, st inventoryLister, host string) ([]string, error) {
	rows, err := st.ListInventory(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		if r.JumpVia == host {
			out = append(out, r.Hostname)
		}
	}
	return out, nil
}

// confirmDelete asks before removing, and refuses to assume when it cannot ask.
// A delete that proceeds unattended because there was no terminal is the same
// mistake as one that proceeds because nobody read the prompt.
func confirmDelete(cur store.InventoryRow) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, fmt.Errorf("refusing to delete without confirmation: pass --yes to proceed non-interactively")
	}
	desc := fmt.Sprintf("%s in %s, reached as %s@%s", cur.IP, cur.DC, cur.User, cur.Hostname)
	if cur.JumpVia != "" {
		desc += " via " + cur.JumpVia
	}
	var ok bool
	err := huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title("Remove " + cur.Hostname + " from the inventory?").
			Description(desc).
			Affirmative("Remove").
			Negative("Cancel").
			Value(&ok),
	)).WithTheme(ui.FormTheme()).WithKeyMap(ui.FormKeyMap()).Run()
	return ok, err
}
