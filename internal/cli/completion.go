package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// Shell completion for the values that are typed most and remembered least: a
// deployment's Keystone endpoint, a Nova uuid, the project a VM belongs to.
//
// Three rules hold for everything in this file, and they come from where a
// completion runs. It is a hidden process spawned by a keystroke, in the middle
// of a line somebody is still typing.
//
//   - It never asks anything. Authenticating here would put a password prompt,
//     or a browser, behind a Tab — so a completion that would need one produces
//     nothing instead.
//   - It never waits. completionBudget is the whole cost of a keypress, and an
//     unreachable database has to cost that and no more.
//   - It never speaks. Anything written to stderr lands in the middle of the
//     command being typed, so stderr is closed for the duration.
//
// Every failure means the same thing: no candidates. A shell that gets nothing
// falls back to the user typing the value, which is where they were anyway.

// completionBudget is what one Tab may cost.
//
// Short on purpose, and short enough to lose some answers. Measured on this
// fleet: a warm process answers in 0.14s, while the first contact with Vault
// and Postgres after an idle period takes about ten seconds — the same ten
// seconds any other vctl command pays there. No budget that belongs on a
// keystroke covers that, so the first Tab of a session can come back empty and
// the next one, after any real command has opened the path, is instant.
//
// That is the trade taken deliberately. A Tab that offers nothing costs the
// user the typing they were already doing; a Tab that freezes the terminal for
// ten seconds looks like a hung shell.
const completionBudget = 2 * time.Second

// completer is cobra's signature for both flag values and positional arguments.
type completer func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective)

// completeFromStore answers a completion out of the inventory database.
//
// fn returns the candidates and nothing else: no error path, because there is
// nowhere to report one. Everything that can fail — building the app,
// authenticating, connecting, querying — collapses to an empty list here.
func (e CommandEnv) completeFromStore(fn func(context.Context, *store.Store, string) []string) completer {
	return func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		defer silenceStderr()()

		a, err := e.newApp()
		if err != nil {
			return noCompletions()
		}
		// The one check that has to happen before anything opens: with no token
		// and no AppRole credentials, opening the store is what triggers the
		// login, and a login triggered from here is a prompt nobody asked for
		// attached to a keystroke.
		if a.WouldPromptForLogin() {
			return noCompletions()
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), completionBudget)
		defer cancel()
		st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
		if err != nil {
			return noCompletions()
		}
		defer st.Close()
		return fn(ctx, st, toComplete), cobra.ShellCompDirectiveNoFileComp
	}
}

// noCompletions is the answer to everything that went wrong.
//
// NoFileComp rather than ShellCompDirectiveError: on an error most shells fall
// back to completing filenames, and offering the contents of the current
// directory as candidates for --farm is worse than offering nothing.
func noCompletions() ([]string, cobra.ShellCompDirective) {
	return nil, cobra.ShellCompDirectiveNoFileComp
}

// silenceStderr redirects stderr for the duration of a completion and returns
// the undo.
//
// Not tidiness. The store path warns about a local DSN, the audit spool reports
// what it flushed — both correct in a command, both written straight into the
// half-typed line here, where the shell has already drawn the prompt and has no
// idea something else printed.
func silenceStderr() func() {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return func() {}
	}
	prev := os.Stderr
	os.Stderr = devnull
	return func() {
		os.Stderr = prev
		_ = devnull.Close()
	}
}

// candidate formats one completion the way cobra reads it: the value, a tab,
// and what to say about it.
//
// The description is what makes a uuid choosable. Tabs and newlines inside it
// would end the value or the line, so they are flattened rather than trusted —
// a VM name comes from nova and nothing here controls what is in it.
func candidate(value, desc string) string {
	desc = strings.Join(strings.Fields(desc), " ")
	if desc == "" {
		return value
	}
	return value + "\t" + desc
}

func hasPrefixFold(s, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
}

// fromStoredFleet answers a completion out of the last stored reading.
//
// Nothing new is stored for this. The snapshot a listing already writes holds
// the probed hosts, their roles, the deployments and the instance rows — which
// is every completion here except projects, whose table is not in it.
//
// The same window as the farm chips, and for the same reason: a Tab is not a
// decision. The worst a day-old list does is fail to offer something added this
// morning, and typing it still works.
func fromStoredFleet(env CommandEnv, shape fleet.Shape, fn func(fleet.Catalog, string) []string) func(string) ([]string, bool) {
	return func(toComplete string) ([]string, bool) {
		a, err := env.newApp()
		if err != nil {
			return nil, false
		}
		rd, ok := storedReader(a).Stored(shape, fleet.ForCompletion)
		if !ok {
			return nil, false
		}
		return fn(rd.Catalog, toComplete), true
	}
}

// completeFarm offers the deployments, by whichever of their two names is being
// typed.
//
// A farm has an id — its Keystone endpoint — and usually a display name, and
// resolveFarm accepts either. The name leads because it is what the listings
// print and what somebody has in mind; the endpoint appears once its own digits
// are being typed, which is the only time anybody wants to see an address in a
// list of names.
//
// extra carries the words a particular flag accepts that are not deployments,
// like the listing's "unassigned".
// The stored reading answers first, the way completeInventoryHost uses the
// local snapshot, and for the same reason twice over. This is the completion a
// Tab reaches for most, and it is the one that most often comes back empty:
// completionBudget is two seconds and the first contact with Vault and Postgres
// after an idle period takes about ten, so the answer that was on disk all
// along was being paid for and then abandoned.
//
// Anything inside the usable window, not just the fresh one. A Tab is not a
// decision — the worst a day-old list can do is fail to offer a farm somebody
// renamed this morning, and typing it still works. Every command that takes the
// value resolves it against the database anyway.
func completeFarm(env CommandEnv, extra ...string) completer {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		restore := silenceStderr()
		if a, err := env.newApp(); err == nil {
			if rd, ok := storedReader(a).Stored(fleet.ShapeFarms, fleet.ForCompletion); ok {
				restore()
				return farmCompletions(rd.Catalog.Farms(), extra, toComplete), cobra.ShellCompDirectiveNoFileComp
			}
		}
		restore()
		return env.completeFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
			// nil app: a completion does not keep what it reads. It runs on a
			// keystroke with a two-second budget, and a write on that path is a
			// disk touch nobody asked for. The listings fill this cache; a Tab
			// only ever reads it.
			farms, err := farmChoices(ctx, nil, st)
			if err != nil {
				return nil
			}
			return farmCompletions(farms, extra, toComplete)
		})(cmd, args, toComplete)
	}
}

func farmCompletions(farms []farmChoice, extra []string, toComplete string) []string {
	out := make([]string, 0, len(farms)+len(extra))
	for _, f := range farms {
		desc := pluralHosts(len(f.Hosts))
		if f.Region != "" {
			desc = f.Region + " · " + desc
		}
		if f.State != "" && f.State != store.StateActive {
			desc += " · " + f.State
		}
		switch {
		case f.Name == "":
			if hasPrefixFold(f.ID, toComplete) {
				out = append(out, candidate(f.ID, desc))
			}
		case hasPrefixFold(f.Name, toComplete):
			out = append(out, candidate(f.Name, f.ID+" · "+desc))
		case toComplete != "" && hasPrefixFold(f.ID, toComplete):
			// Somebody typing an address means the address.
			out = append(out, candidate(f.ID, f.Name+" · "+desc))
		}
	}
	for _, v := range extra {
		if hasPrefixFold(v, toComplete) {
			out = append(out, v)
		}
	}
	return out
}

// completeOpenStackHost offers the physical hosts a probe has reported on.
//
// detectedOnly for --host, which asks which VMs sit on a machine: a host with
// no OpenStack on it has no answer to that. `openstack host` takes the wider
// set, because "probed, found nothing" is exactly what that command is for
// showing.
func completeOpenStackHost(env CommandEnv, detectedOnly bool) completer {
	stored := fromStoredFleet(env, fleet.ShapeFarms, func(cat fleet.Catalog, tc string) []string {
		return openStackHostCompletions(cat.Hosts(), detectedOnly, tc)
	})
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		restore := silenceStderr()
		if out, ok := stored(toComplete); ok {
			restore()
			return out, cobra.ShellCompDirectiveNoFileComp
		}
		restore()
		return env.completeFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
			hosts, err := st.OpenStackHosts(ctx)
			if err != nil {
				return nil
			}
			return openStackHostCompletions(hosts, detectedOnly, toComplete)
		})(cmd, args, toComplete)
	}
}

func openStackHostCompletions(hosts []store.OpenStackHost, detectedOnly bool, toComplete string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if detectedOnly && !h.Detected {
			continue
		}
		if !hasPrefixFold(h.Hostname, toComplete) {
			continue
		}
		desc := rolesSummary(h.Roles, false)
		if h.FarmName != "" {
			desc = h.FarmName + " · " + desc
		} else if h.Farm != "" {
			desc = h.Farm + " · " + desc
		}
		out = append(out, candidate(h.Hostname, desc))
	}
	return out
}

// completeRole offers the roles that are actually held, with how many hosts
// hold each.
//
// Not a fixed list. rolePrecedence names nine, a farm here reports more than
// that, and a hard-coded set would quietly stop matching the fleet the first
// time a deployment gained a service. Dropped roles are left out for the reason
// the filter ignores them: --role compute has to mean a machine running nova
// now.
func completeRole(env CommandEnv) completer {
	stored := fromStoredFleet(env, fleet.ShapeFarms, func(cat fleet.Catalog, tc string) []string {
		return roleCompletions(cat.Hosts(), tc)
	})
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		restore := silenceStderr()
		if out, ok := stored(toComplete); ok {
			restore()
			return out, cobra.ShellCompDirectiveNoFileComp
		}
		restore()
		return env.completeFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
			hosts, err := st.OpenStackHosts(ctx)
			if err != nil {
				return nil
			}
			return roleCompletions(hosts, toComplete)
		})(cmd, args, toComplete)
	}
}

func roleCompletions(hosts []store.OpenStackHost, toComplete string) []string {
	count := map[string]int{}
	for _, h := range hosts {
		for _, r := range h.Roles {
			count[r]++
		}
	}
	roles := make([]string, 0, len(count))
	for r := range count {
		if hasPrefixFold(r, toComplete) {
			roles = append(roles, r)
		}
	}
	sort.Strings(roles)
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, candidate(r, pluralHosts(count[r])))
	}
	return out
}

// completeProject offers the tenants that own VMs.
//
// By name, since that is the column the table prints — the same asymmetry
// resolveProjects fixes on the input side. The id follows in the description,
// and leads when its own characters are being typed.
func completeProject(env CommandEnv) completer {
	return env.completeFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
		projects, err := st.Projects(ctx, "")
		if err != nil {
			return nil
		}
		names, err := farmNames(ctx, st)
		if err != nil {
			return nil
		}
		return projectCompletions(projects, names, toComplete)
	})
}

func projectCompletions(projects []store.Project, farms map[string]string, toComplete string) []string {
	// A name means a different project in every farm, and offering it once per
	// farm would fill the menu with what looks like a repeated entry. It is
	// offered once, and the count says how much it covers; --farm is how one of
	// them gets picked, which is what resolveProjects says when it is used
	// wide.
	type entry struct {
		desc  string
		farms map[string]bool
		vms   int
	}
	byName := map[string]*entry{}
	order := make([]string, 0, len(projects))
	out := make([]string, 0, len(projects))
	for _, p := range projects {
		if p.Name == "" {
			// Nothing resolved a name for it, so the id is the only handle.
			if hasPrefixFold(p.ID, toComplete) {
				out = append(out, candidate(p.ID, farmLabelOf(p.DeploymentID, farms)))
			}
			continue
		}
		if !hasPrefixFold(p.Name, toComplete) {
			if toComplete != "" && hasPrefixFold(p.ID, toComplete) {
				out = append(out, candidate(p.ID, p.Name+" · "+farmLabelOf(p.DeploymentID, farms)))
			}
			continue
		}
		e, ok := byName[p.Name]
		if !ok {
			e = &entry{farms: map[string]bool{}}
			byName[p.Name] = e
			order = append(order, p.Name)
		}
		e.farms[p.DeploymentID] = true
		e.vms += p.VMs
		e.desc = farmLabelOf(p.DeploymentID, farms)
	}
	for _, name := range order {
		e := byName[name]
		desc := fmt.Sprintf("%s · %d VMs", e.desc, e.vms)
		if len(e.farms) > 1 {
			desc = fmt.Sprintf("%d farms · %d VMs", len(e.farms), e.vms)
		}
		out = append(out, candidate(name, desc))
	}
	return out
}

// farmLabelOf is the name if the farm has one, the endpoint otherwise.
// Nothing claims the farm is unnamed — an endpoint is a real answer to
// "which one". Shared with the VM listing, which carried a byte-identical
// copy under another name.
func farmLabelOf(id string, farms map[string]string) string {
	if n := farms[id]; n != "" {
		return n
	}
	return id
}

// completeVM offers Nova uuids, described by the VM they belong to.
//
// This is the completion the review was really about. `vctl ssh --vm` takes a
// uuid and nothing else, because a name that fits two VMs must not be resolved
// by position — which left the identifier a person needs to type as the one
// thing no listing put in front of them by default. Here the value is the uuid
// and the name is the description, so the menu is read by name and what lands
// on the line is the identity.
//
// Missing VMs are left out: nova no longer lists them, and nothing good comes
// of completing a connection to one.
func completeVM(env CommandEnv) completer {
	stored := fromStoredFleet(env, fleet.ShapeVMs, func(cat fleet.Catalog, tc string) []string {
		return vmCompletions(cat.AllVMs(), cat.Names(), tc)
	})
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		restore := silenceStderr()
		if out, ok := stored(toComplete); ok {
			restore()
			return out, cobra.ShellCompDirectiveNoFileComp
		}
		restore()
		return env.completeFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
			vms, err := st.Instances(ctx, store.InstanceFilter{})
			if err != nil {
				return nil
			}
			names, err := farmNames(ctx, st)
			if err != nil {
				return nil
			}
			return vmCompletions(vms, names, toComplete)
		})(cmd, args, toComplete)
	}
}

func vmCompletions(vms []store.Instance, farms map[string]string, toComplete string) []string {
	// Kubernetes writes providerIDs as openstack:///<uuid> and that is what
	// gets pasted, so a line already carrying the prefix still completes.
	toComplete = strings.TrimPrefix(toComplete, providerIDPrefix)
	out := make([]string, 0, len(vms))
	for _, v := range vms {
		if !hasPrefixFold(v.InstanceID, toComplete) {
			continue
		}
		desc := nameOrID(v)
		if desc == v.InstanceID {
			desc = "unnamed"
		}
		desc += " · " + farmLabelOf(v.DeploymentID, farms)
		if s := strings.ToUpper(v.Status); s != "" && s != "ACTIVE" {
			desc += " · " + s
		}
		out = append(out, candidate(v.InstanceID, desc))
	}
	return out
}

// completeVMName offers what the VMs are called, for the argument that
// searches.
//
// The listing's positional takes a fragment of a name or an address, so a uuid
// there would be the wrong shape of help — and a name that fits several VMs is
// a legitimate answer to it, unlike on the paths that connect.
func completeVMName(env CommandEnv) completer {
	stored := fromStoredFleet(env, fleet.ShapeVMs, func(cat fleet.Catalog, tc string) []string {
		return vmNameCompletions(cat.AllVMs(), cat.Names(), tc)
	})
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		restore := silenceStderr()
		if out, ok := stored(toComplete); ok {
			restore()
			return out, cobra.ShellCompDirectiveNoFileComp
		}
		restore()
		return env.completeFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
			vms, err := st.Instances(ctx, store.InstanceFilter{})
			if err != nil {
				return nil
			}
			names, err := farmNames(ctx, st)
			if err != nil {
				return nil
			}
			return vmNameCompletions(vms, names, toComplete)
		})(cmd, args, toComplete)
	}
}

func vmNameCompletions(vms []store.Instance, farms map[string]string, toComplete string) []string {
	type entry struct {
		farms map[string]bool
		desc  string
	}
	seen := map[string]*entry{}
	order := make([]string, 0, len(vms))
	for _, v := range vms {
		if v.Name == "" || !hasPrefixFold(v.Name, toComplete) {
			continue
		}
		e, ok := seen[v.Name]
		if !ok {
			e = &entry{farms: map[string]bool{}}
			seen[v.Name] = e
			order = append(order, v.Name)
		}
		e.farms[v.DeploymentID] = true
		e.desc = farmLabelOf(v.DeploymentID, farms)
	}
	out := make([]string, 0, len(order))
	for _, name := range order {
		e := seen[name]
		desc := e.desc
		if len(e.farms) > 1 {
			// A name in two farms is two machines. The search will return both,
			// and saying so here is cheaper than finding out from the table.
			desc = fmt.Sprintf("%d farms", len(e.farms))
		}
		out = append(out, candidate(name, desc))
	}
	return out
}

// completeInventoryHost offers the hosts vctl can connect to.
//
// The inventory rather than the OpenStack view: this is what `vctl ssh` and
// --server resolve against, and most of the fleet is not an OpenStack machine.
// Retired hosts are left out — the row is kept as a record and connecting to
// one is not what anybody is completing towards.
//
// The local snapshot answers first, which is the opposite of every other path
// here. Two reasons, and neither applies to farms or VMs. It is the completion
// somebody presses constantly, and the snapshot has exactly what it needs — so
// paying the database for it is paying for something already on disk. And the
// snapshot is what `vctl ssh` itself falls back to when Postgres is gone, so
// completing from it during an outage offers the same hosts the command will
// still resolve.
func completeInventoryHost(env CommandEnv) completer {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		restore := silenceStderr()
		if a, err := env.newApp(); err == nil && !a.Cfg.CacheDisabled {
			snap, err := a.CacheFile().Load()
			if err == nil && snap.HasInventory() && !snap.Expired(time.Now(), a.Cfg.CacheStaleLimit()) {
				servers := make([]store.Server, 0, len(snap.Servers))
				for _, s := range snap.Servers {
					servers = append(servers, s.Server)
				}
				restore()
				return inventoryHostCompletions(servers, toComplete), cobra.ShellCompDirectiveNoFileComp
			}
		}
		restore()
		return env.completeFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
			servers, err := st.List(ctx, "")
			if err != nil {
				return nil
			}
			return inventoryHostCompletions(servers, toComplete)
		})(cmd, args, toComplete)
	}
}

func inventoryHostCompletions(servers []store.Server, toComplete string) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		if s.State == store.StateRetired || !hasPrefixFold(s.Hostname, toComplete) {
			continue
		}
		desc := s.DC
		if s.State != "" && s.State != store.StateActive {
			desc = strings.TrimPrefix(desc+" · "+s.State, " · ")
		}
		out = append(out, candidate(s.Hostname, desc))
	}
	return out
}

// staticCompletions offers a fixed set — a flag whose values are a contract
// rather than data. It touches nothing, so it answers during an outage too.
//
// The value may carry its own description after a tab, the same as any other
// candidate.
func staticCompletions(values ...string) completer {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		out := make([]string, 0, len(values))
		for _, v := range values {
			if hasPrefixFold(v, toComplete) {
				out = append(out, v)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// byPosition dispatches on which argument is being typed: the first completer
// answers the first argument, the second the second, and anything past the end
// gets nothing.
//
// `farm state <deployment> <state>` is two different questions in one line, and
// offering the deployments again in the second position would suggest a farm
// where only four words are legal.
func byPosition(fns ...completer) completer {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) >= len(fns) {
			return noCompletions()
		}
		return fns[len(args)](cmd, args, toComplete)
	}
}

// registerCompletion attaches a completer to a flag. cobra reports the flag not
// existing, which is a wiring mistake rather than a runtime condition, so it
// panics here rather than leaving a flag silently uncompleted.
func registerCompletion(cmd *cobra.Command, flag string, fn completer) {
	if err := cmd.RegisterFlagCompletionFunc(flag, fn); err != nil {
		panic(fmt.Sprintf("completion for --%s on %q: %v", flag, cmd.Name(), err))
	}
}
