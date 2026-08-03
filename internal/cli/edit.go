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

// editCmd changes the operator-managed fields of a host already in inventory.
//
// These are exactly the columns `vctl sync` refuses to touch — dc, ssh_user,
// jump_via, extra_ips — because sync derives its view from ssh config and
// probes, and would otherwise overwrite decisions a person made. That makes
// them unreachable except through cmd/dbedit, a separate binary nobody has on
// the machine where they notice the problem.
//
// Each flag is optional and only what is passed gets written. A command that
// rewrote every field from its defaults would silently blank the ones the
// operator did not mention, which is the failure a partial edit exists to
// avoid.
func editCmd() *cobra.Command {
	var e hostEdits
	cmd := &cobra.Command{
		Use:   "edit <hostname>",
		Short: "Change an inventory host's operator-managed fields",
		Long: `edit changes the fields vctl sync will not overwrite: datacenter,
SSH user, jump host and extra addresses. It can also rename a host.

Only the flags you pass are written. Run with just a hostname to pick the
fields interactively.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			host := args[0]
			return withStore(ctx, true, func(_ *app.App, st *store.Store) error {
				cur, err := findHost(ctx, st, host)
				if err != nil {
					return err
				}
				if e.empty() {
					if !term.IsTerminal(int(os.Stdin.Fd())) {
						return fmt.Errorf("nothing to change: pass at least one of --dc, --user, --jump, --extra-ip, --name")
					}
					if err := e.prompt(cur); err != nil {
						return err
					}
				}
				if e.empty() {
					ui.Infof(os.Stdout, "no changes")
					return nil
				}
				if err := e.validate(ctx, st, host); err != nil {
					return err
				}
				return e.apply(ctx, st, host)
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&e.DC, "dc", "", "datacenter label")
	f.StringVar(&e.User, "user", "", "SSH login user")
	f.StringVar(&e.JumpVia, "jump", "", `jump host; pass "direct" to clear it`)
	f.StringVar(&e.Name, "name", "", "rename the host (jump chains that point at it are repointed)")
	f.StringSliceVar(&e.ExtraIPs, "extra-ip", nil, "replace the extra addresses (repeatable; pass none to clear)")
	f.BoolVar(&e.clearIPs, "clear-extra-ips", false, "remove every extra address")
	return gate(cmd, "edit", classMutate)
}

// hostEdits is the set of changes a caller asked for. A field left zero was not
// mentioned and is not written — the distinction between "set this to empty"
// and "do not touch this" is the whole contract, so clearing has explicit
// spellings (--jump direct, --clear-extra-ips) rather than an empty value.
type hostEdits struct {
	DC       string
	User     string
	JumpVia  string
	Name     string
	ExtraIPs []string
	clearIPs bool
}

func (e hostEdits) empty() bool {
	return e.DC == "" && e.User == "" && e.JumpVia == "" && e.Name == "" &&
		len(e.ExtraIPs) == 0 && !e.clearIPs
}

// apply writes each requested change, reporting what actually landed. A rename
// goes last: everything before it is keyed by the old hostname.
func (e hostEdits) apply(ctx context.Context, st *store.Store, host string) error {
	type step struct {
		label string
		run   func() (bool, error)
	}
	var steps []step
	if e.DC != "" {
		steps = append(steps, step{"dc=" + e.DC, func() (bool, error) { return st.SetDC(ctx, host, e.DC) }})
	}
	if e.User != "" {
		steps = append(steps, step{"user=" + e.User, func() (bool, error) { return st.SetUser(ctx, host, e.User) }})
	}
	if e.clearIPs {
		steps = append(steps, step{"extra-ips=(none)", func() (bool, error) { return st.SetExtraIPs(ctx, host, nil) }})
	} else if len(e.ExtraIPs) > 0 {
		ips := e.ExtraIPs
		steps = append(steps, step{
			fmt.Sprintf("extra-ips=%d", len(ips)),
			func() (bool, error) { return st.SetExtraIPs(ctx, host, ips) },
		})
	}
	if e.JumpVia != "" {
		jump := e.JumpVia
		label := "jump=" + jump
		if jump == jumpDirect {
			jump, label = "", "jump=(direct)"
		}
		steps = append(steps, step{label, func() (bool, error) { return st.SetJumpVia(ctx, host, jump) }})
	}
	if e.Name != "" {
		steps = append(steps, step{"name=" + e.Name, func() (bool, error) { return st.Rename(ctx, host, e.Name) }})
	}

	for _, s := range steps {
		ok, err := s.run()
		if err != nil {
			return fmt.Errorf("%s: %w", s.label, err)
		}
		if !ok {
			return fmt.Errorf("%s: no host named %q", s.label, host)
		}
		ui.Successf(os.Stdout, "%s  %s", host, s.label)
	}
	return nil
}

// validate rejects edits the database would take but `vctl ssh` could not use,
// mirroring what add checks at creation time.
func (e hostEdits) validate(ctx context.Context, st inventoryLister, host string) error {
	for _, ip := range e.ExtraIPs {
		if net.ParseIP(strings.TrimSpace(ip)) == nil {
			return fmt.Errorf("invalid --extra-ip: %q", ip)
		}
	}
	if e.Name == host {
		return fmt.Errorf("--name is the current hostname")
	}
	if e.JumpVia == "" || e.JumpVia == jumpDirect {
		return nil
	}
	target := e.Name
	if target == "" {
		target = host
	}
	if e.JumpVia == target {
		return fmt.Errorf("--jump points at the host itself")
	}
	return jumpHostExists(ctx, st, e.JumpVia)
}

// jumpDirect is the explicit spelling for "no jump host". An empty --jump means
// "leave it alone", so clearing needs a word.
const jumpDirect = "direct"

// findHost resolves the hostname before anything is written, so a typo fails
// with a name rather than a silent no-op on every step.
func findHost(ctx context.Context, st inventoryLister, host string) (store.InventoryRow, error) {
	rows, err := st.ListInventory(ctx, "")
	if err != nil {
		return store.InventoryRow{}, err
	}
	for _, r := range rows {
		if r.Hostname == host {
			return r, nil
		}
	}
	return store.InventoryRow{}, fmt.Errorf("no host named %q in the inventory", host)
}

// jumpHostExists is shared with add: a jump host that is not registered makes a
// row that stores cleanly and fails at connect time.
func jumpHostExists(ctx context.Context, st inventoryLister, jump string) error {
	if st == nil {
		return nil
	}
	rows, err := st.ListInventory(ctx, "")
	if err != nil {
		return nil // a courtesy check; do not fail the edit on it
	}
	for _, r := range rows {
		if r.Hostname == jump {
			return nil
		}
	}
	return fmt.Errorf("jump host %q is not in the inventory", jump)
}

// prompt asks which fields to change, seeded with what the host has now so the
// operator edits rather than retypes.
func (e *hostEdits) prompt(cur store.InventoryRow) error {
	dc, user := cur.DC, cur.User
	jump := cur.JumpVia
	if jump == "" {
		jump = jumpDirect
	}
	extra := strings.Join(cur.ExtraIPs, ", ")

	form := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("Datacenter").Value(&dc).Validate(nonEmpty("datacenter")),
		huh.NewInput().Title("SSH user").Value(&user).Validate(nonEmpty("user")),
		huh.NewInput().Title("Jump host").
			Description(`an inventory hostname, or "direct"`).
			Value(&jump),
		huh.NewInput().Title("Other addresses").
			Description("comma separated; empty clears them").
			Value(&extra).
			Validate(func(s string) error {
				for _, ip := range splitIPList(s) {
					if net.ParseIP(ip) == nil {
						return fmt.Errorf("%q is not an IP address", ip)
					}
				}
				return nil
			}),
	))
	if err := form.WithTheme(ui.FormTheme()).Run(); err != nil {
		return err
	}

	// Only differences become edits. Echoing the current value back must not
	// count as a change, or every prompted run would rewrite all four columns
	// and the output would claim work that did not happen.
	if dc = strings.TrimSpace(dc); dc != cur.DC {
		e.DC = dc
	}
	if user = strings.TrimSpace(user); user != cur.User {
		e.User = user
	}
	if jump = strings.TrimSpace(jump); jump != cur.JumpVia && !(jump == jumpDirect && cur.JumpVia == "") {
		e.JumpVia = jump
	}
	got := splitIPList(extra)
	if !sameStrings(got, cur.ExtraIPs) {
		if len(got) == 0 {
			e.clearIPs = true
		} else {
			e.ExtraIPs = got
		}
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
