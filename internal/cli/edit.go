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
// them unreachable except through a separate maintenance binary nobody had on
// the machine where they notice the problem.
//
// Each flag is optional and only what is passed gets written. A command that
// rewrote every field from its defaults would silently blank the ones the
// operator did not mention, which is the failure a partial edit exists to
// avoid.
func editCmd(env CommandEnv) *cobra.Command {
	var e hostEdits
	cmd := &cobra.Command{
		Use:   "edit [hostname]",
		Short: "Change an inventory host's operator-managed fields",
		Long: `edit changes the fields vctl sync will not overwrite: datacenter,
SSH user, jump host and extra addresses. It can also rename a host.

Run with no hostname to pick one from the inventory. Only the flags you pass
are written; with none, the fields are asked for interactively.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return env.withStore(ctx, true, func(_ *app.App, st *store.Store) error {
				cur, err := resolveHost(ctx, st, args, "Edit which host?")
				if err != nil {
					return err
				}
				host := cur.Hostname
				if e.empty() {
					if !term.IsTerminal(int(os.Stdin.Fd())) {
						return fmt.Errorf("nothing to change: pass at least one of --dc, --user, --jump, --extra-ip, --name, --state")
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
				if err := e.apply(ctx, st, host); err != nil {
					return err
				}
				warnAgentAfterRename(cur, e.Name)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&e.DC, "dc", "", "datacenter label")
	f.StringVar(&e.User, "user", "", "SSH login user")
	f.StringVar(&e.JumpVia, "jump", "", `jump host; pass "direct" to clear it`)
	f.StringVar(&e.Name, "name", "", "rename the host (jump chains that point at it are repointed)")
	f.StringVar(&e.State, "state", "", "operator-declared state: "+strings.Join(store.HostStates, "|"))
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
	State    string
	ExtraIPs []string
	clearIPs bool
}

func (e hostEdits) empty() bool {
	return e.DC == "" && e.User == "" && e.JumpVia == "" && e.Name == "" && e.State == "" &&
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
	if e.State != "" {
		state := e.State
		steps = append(steps, step{"state=" + state, func() (bool, error) { return st.SetState(ctx, host, state) }})
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

// warnAgentAfterRename says the one thing a rename cannot fix from here.
//
// node-agent is started with the inventory hostname baked into its systemd unit
// (`vctl node-agent --hostname <name>`), because OS names do not match inventory
// names. The database rename carries the heartbeat row, but the agent keeps
// reporting under the old name on its next tick and UpsertServerStatus drops it
// as unregistered. The host then reads as no-agent until the vctl_host Ansible
// role runs again.
//
// Nothing here can reach the host to fix that, so the least it can do is not let
// the operator find out ten minutes later from a listing. Hosts that never had
// an agent are silent: there is no unit to update.
func warnAgentAfterRename(cur store.InventoryRow, newName string) {
	if newName == "" || cur.AgentSeen == nil {
		return
	}
	ui.Warnf(os.Stderr, "node-agent on this host still reports as %s", cur.Hostname)
	ui.Infof(os.Stderr, "re-run the vctl_host Ansible role against it, or its status goes stale")
}

// validate rejects edits the database would take but `vctl ssh` could not use,
// mirroring what add checks at creation time.
func (e hostEdits) validate(ctx context.Context, st inventoryLister, host string) error {
	for _, ip := range e.ExtraIPs {
		if net.ParseIP(strings.TrimSpace(ip)) == nil {
			return fmt.Errorf("invalid --extra-ip: %q", ip)
		}
	}
	// Reject an unknown state before any other step writes. The database has the
	// same constraint, but hitting it mid-apply would leave the earlier edits
	// committed and report a check-constraint name instead of the valid words.
	if e.State != "" && !store.ValidState(e.State) {
		return fmt.Errorf("unknown --state %q (want one of %s)", e.State, strings.Join(store.HostStates, ", "))
	}
	if e.Name == host {
		return fmt.Errorf("--name is the current hostname")
	}
	// servers.hostname is UNIQUE, so a taken name fails in the database with a
	// constraint violation naming an index. Catching it here says which host
	// already has the name, which is the thing the operator needs to know.
	if e.Name != "" {
		if _, err := findHost(ctx, st, e.Name); err == nil {
			return fmt.Errorf("%q is already in the inventory", e.Name)
		}
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
	name := cur.Hostname
	state := store.StateOrActive(cur.State)
	dc, user := cur.DC, cur.User
	jump := cur.JumpVia
	if jump == "" {
		jump = jumpDirect
	}
	extra := strings.Join(cur.ExtraIPs, ", ")

	form := huh.NewForm(huh.NewGroup(
		// Last, not first. The name is the inventory key and the field least
		// often being changed, so it should not be what the cursor lands on when
		// someone opens the form to fix a datacenter label.
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
		// A Select, not free text: the database constrains the column, and typing
		// "down" into a field that only takes these four should fail at the form
		// rather than after the other edits have already been written.
		huh.NewSelect[string]().Title("State").
			Description("what you are declaring; liveness stays observed and is shown next to it\n"+stateMeanings()).
			Options(stateOptions()...).
			Value(&state).
			Inline(true),
		huh.NewInput().Title("Hostname").
			Description("renaming carries the agent heartbeat and jump chains; audit history keeps the old name").
			Value(&name).
			Validate(nonEmpty("hostname")),
	))
	if err := form.WithTheme(ui.FormTheme()).WithKeyMap(ui.FormKeyMap()).Run(); err != nil {
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
	if name = strings.TrimSpace(name); name != cur.Hostname {
		e.Name = name
	}
	if state != store.StateOrActive(cur.State) {
		e.State = state
	}
	return nil
}

// stateOptions labels each state with what it means for the listing, because
// the words alone do not say which of them silence a red row and which do not.
//
// Nothing here marks the current value: the field is bound to a variable already
// holding it, and huh selects the option matching that. Setting it twice would
// be two mechanisms for one behaviour, and they can disagree.
// stateOptions are the words the database accepts, and only the words.
//
// The meanings live in stateMeanings rather than in the labels because the
// field is inline: it renders one value at a time, so a label carrying its own
// explanation would show one state's meaning and hide the other three.
func stateOptions() []huh.Option[string] {
	opts := make([]huh.Option[string], 0, len(store.HostStates))
	for _, s := range store.HostStates {
		opts = append(opts, huh.NewOption(s, s))
	}
	return opts
}

// stateMeanings is the whole set at once, under the field.
//
// All four are shown whichever one is selected. Declaring a state is a claim
// about what to expect, and choosing between them needs the alternatives in
// view — "broken" only means something next to "maintenance".
func stateMeanings() string {
	return "active: expected up, a down reading is a problem\n" +
		"maintenance: planned window, down is expected and temporary\n" +
		"broken: known faulty, somebody diagnosed it\n" +
		"retired: decommissioned, kept for its history"
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
