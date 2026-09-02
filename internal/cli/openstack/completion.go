package openstack

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// fromStoredFleet answers a completion out of the last stored reading.
//
// Nothing new is stored for this. The snapshot a listing already writes holds
// the probed hosts, their roles, the deployments and the instance rows — which
// is every completion here except projects, whose table is not in it.
//
// The same window as the farm chips, and for the same reason: a Tab is not a
// decision. The worst a day-old list does is fail to offer something added this
// morning, and typing it still works.
func fromStoredFleet(env cmdkit.Env, shape fleet.Shape, fn func(fleet.Catalog, string) []string) func(string) ([]string, bool) {
	return func(toComplete string) ([]string, bool) {
		a, err := env.App()
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

// CompleteFarm offers the deployments, by whichever of their two names is being
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
// cmdkit.CompletionBudget is two seconds and the first contact with Vault and Postgres
// after an idle period takes about ten, so the answer that was on disk all
// along was being paid for and then abandoned.
//
// Anything inside the usable window, not just the fresh one. A Tab is not a
// decision — the worst a day-old list can do is fail to offer a farm somebody
// renamed this morning, and typing it still works. Every command that takes the
// value resolves it against the database anyway.
func CompleteFarm(env cmdkit.Env, extra ...string) cmdkit.Completer {
	return cmdkit.StoredThenStore(env,
		fromStoredFleet(env, fleet.ShapeFarms, func(cat fleet.Catalog, tc string) []string {
			return farmCompletions(cat.Farms(), extra, tc)
		}),
		func(ctx context.Context, st *store.Store, toComplete string) []string {
			// nil app: a completion does not keep what it reads. It runs on a
			// keystroke with a two-second budget, and a write on that path is a
			// disk touch nobody asked for. The listings fill this cache; a Tab
			// only ever reads it.
			farms, err := farmChoices(ctx, nil, st)
			if err != nil {
				return nil
			}
			return farmCompletions(farms, extra, toComplete)
		})
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
			if cmdkit.HasPrefixFold(f.ID, toComplete) {
				out = append(out, cmdkit.Candidate(f.ID, desc))
			}
		case cmdkit.HasPrefixFold(f.Name, toComplete):
			out = append(out, cmdkit.Candidate(f.Name, f.ID+" · "+desc))
		case toComplete != "" && cmdkit.HasPrefixFold(f.ID, toComplete):
			// Somebody typing an address means the address.
			out = append(out, cmdkit.Candidate(f.ID, f.Name+" · "+desc))
		}
	}
	for _, v := range extra {
		if cmdkit.HasPrefixFold(v, toComplete) {
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
func completeOpenStackHost(env cmdkit.Env, detectedOnly bool) cmdkit.Completer {
	return cmdkit.StoredThenStore(env, fromStoredFleet(env, fleet.ShapeFarms, func(cat fleet.Catalog, tc string) []string {
		return openStackHostCompletions(cat.Hosts(), detectedOnly, tc)
	}), func(ctx context.Context, st *store.Store, toComplete string) []string {
		hosts, err := st.OpenStackHosts(ctx)
		if err != nil {
			return nil
		}
		return openStackHostCompletions(hosts, detectedOnly, toComplete)
	})
}

func openStackHostCompletions(hosts []store.OpenStackHost, detectedOnly bool, toComplete string) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if detectedOnly && !h.Detected {
			continue
		}
		if !cmdkit.HasPrefixFold(h.Hostname, toComplete) {
			continue
		}
		desc := rolesSummary(h.Roles, false)
		if h.FarmName != "" {
			desc = h.FarmName + " · " + desc
		} else if h.Farm != "" {
			desc = h.Farm + " · " + desc
		}
		out = append(out, cmdkit.Candidate(h.Hostname, desc))
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
func completeRole(env cmdkit.Env) cmdkit.Completer {
	return cmdkit.StoredThenStore(env, fromStoredFleet(env, fleet.ShapeFarms, func(cat fleet.Catalog, tc string) []string {
		return roleCompletions(cat.Hosts(), tc)
	}), func(ctx context.Context, st *store.Store, toComplete string) []string {
		hosts, err := st.OpenStackHosts(ctx)
		if err != nil {
			return nil
		}
		return roleCompletions(hosts, toComplete)
	})
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
		if cmdkit.HasPrefixFold(r, toComplete) {
			roles = append(roles, r)
		}
	}
	sort.Strings(roles)
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		out = append(out, cmdkit.Candidate(r, pluralHosts(count[r])))
	}
	return out
}

// completeProject offers the tenants that own VMs.
//
// By name, since that is the column the table prints — the same asymmetry
// resolveProjects fixes on the input side. The id follows in the description,
// and leads when its own characters are being typed.
func completeProject(env cmdkit.Env) cmdkit.Completer {
	return env.CompleteFromStore(func(ctx context.Context, st *store.Store, toComplete string) []string {
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
			if cmdkit.HasPrefixFold(p.ID, toComplete) {
				out = append(out, cmdkit.Candidate(p.ID, farmLabelOf(p.DeploymentID, farms)))
			}
			continue
		}
		if !cmdkit.HasPrefixFold(p.Name, toComplete) {
			if toComplete != "" && cmdkit.HasPrefixFold(p.ID, toComplete) {
				out = append(out, cmdkit.Candidate(p.ID, p.Name+" · "+farmLabelOf(p.DeploymentID, farms)))
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
		out = append(out, cmdkit.Candidate(name, desc))
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

// CompleteVM offers Nova uuids, described by the VM they belong to.
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
func CompleteVM(env cmdkit.Env) cmdkit.Completer {
	return cmdkit.StoredThenStore(env, fromStoredFleet(env, fleet.ShapeVMs, func(cat fleet.Catalog, tc string) []string {
		return vmCompletions(cat.AllVMs(), cat.Names(), tc)
	}), func(ctx context.Context, st *store.Store, toComplete string) []string {
		vms, err := st.Instances(ctx, store.InstanceFilter{})
		if err != nil {
			return nil
		}
		names, err := farmNames(ctx, st)
		if err != nil {
			return nil
		}
		return vmCompletions(vms, names, toComplete)
	})
}

func vmCompletions(vms []store.Instance, farms map[string]string, toComplete string) []string {
	// Kubernetes writes providerIDs as openstack:///<uuid> and that is what
	// gets pasted, so a line already carrying the prefix still completes.
	toComplete = strings.TrimPrefix(toComplete, providerIDPrefix)
	out := make([]string, 0, len(vms))
	for _, v := range vms {
		if !cmdkit.HasPrefixFold(v.InstanceID, toComplete) {
			continue
		}
		desc := NameOrID(v)
		if desc == v.InstanceID {
			desc = "unnamed"
		}
		desc += " · " + farmLabelOf(v.DeploymentID, farms)
		if s := strings.ToUpper(v.Status); s != "" && s != "ACTIVE" {
			desc += " · " + s
		}
		out = append(out, cmdkit.Candidate(v.InstanceID, desc))
	}
	return out
}

// completeVMName offers what the VMs are called, for the argument that
// searches.
//
// The listing's positional takes a fragment of a name or an address, so a uuid
// there would be the wrong shape of help — and a name that fits several VMs is
// a legitimate answer to it, unlike on the paths that connect.
func completeVMName(env cmdkit.Env) cmdkit.Completer {
	return cmdkit.StoredThenStore(env, fromStoredFleet(env, fleet.ShapeVMs, func(cat fleet.Catalog, tc string) []string {
		return vmNameCompletions(cat.AllVMs(), cat.Names(), tc)
	}), func(ctx context.Context, st *store.Store, toComplete string) []string {
		vms, err := st.Instances(ctx, store.InstanceFilter{})
		if err != nil {
			return nil
		}
		names, err := farmNames(ctx, st)
		if err != nil {
			return nil
		}
		return vmNameCompletions(vms, names, toComplete)
	})
}

func vmNameCompletions(vms []store.Instance, farms map[string]string, toComplete string) []string {
	type entry struct {
		farms map[string]bool
		desc  string
	}
	seen := map[string]*entry{}
	order := make([]string, 0, len(vms))
	for _, v := range vms {
		if v.Name == "" || !cmdkit.HasPrefixFold(v.Name, toComplete) {
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
		out = append(out, cmdkit.Candidate(name, desc))
	}
	return out
}
