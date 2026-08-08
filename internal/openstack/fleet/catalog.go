// Package fleet turns one reading of the database into the picture people ask
// the OpenStack commands for: which deployments there are, what is in each, and
// which one a typed word means.
//
// It exists because four commands were assembling that picture separately. Each
// read the deployments and the probed hosts for itself, each decided on its own
// which hosts count towards a farm, and two of them read the same tables twice
// in one run. The rules agreed by inspection rather than by construction, and
// the readings were minutes apart in the worst case and statements apart in the
// common one.
//
// The catalog is built from a single store.Fleet, so everything it answers is
// one instant. Nothing here reads, writes, or contacts anything.
package fleet

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// Farm is one deployment and what belongs to it.
//
// The fields a person picks by — the name, the counts, whether anything has
// confirmed it lately — are here rather than derived at each call site, because
// deriving them at each call site is what let two screens disagree about how
// many hosts a farm has.
type Farm struct {
	ID     string
	Name   string
	Region string
	State  string

	// Hosts are the machines a probe found OpenStack on and something has
	// placed in this deployment.
	Hosts []store.OpenStackHost

	// Unsettled counts hosts placed here by local evidence alone — no control
	// plane has confirmed them.
	Unsettled int
}

// A farm carries what identifies it and nothing else. Its VMs and its last
// reconcile live on the Catalog, and only the full reading has them — so a
// caller holding farms from the light reading cannot ask for a VM list and be
// handed an empty one that looks like an answer.

// Named reports whether anybody has given this deployment a name. An endpoint
// is a real answer to "which one", so this is not an error state.
func (f Farm) Named() bool { return f.Name != "" }

// Label is what to call the farm on screen: the name when it has one, the
// Keystone endpoint when it does not.
func (f Farm) Label() string {
	if f.Name != "" {
		return f.Name
	}
	return f.ID
}

// Retired reports whether an operator has declared this deployment out of
// service. Reconcile and the default listing both leave those alone.
func (f Farm) Retired() bool { return f.State == store.StateRetired }

// RoleCounts is how many hosts hold each role — what a deployment is made of,
// which is the question a list of nine hosts each carrying nine roles does not
// answer.
func (f Farm) RoleCounts() map[string]int {
	out := map[string]int{}
	for _, h := range f.Hosts {
		for _, r := range h.Roles {
			out[r]++
		}
	}
	return out
}

// Catalog is the whole fleet at one instant.
type Catalog struct {
	farms []Farm
	byID  map[string]int
	vms   map[string][]store.Instance
	snap  store.Fleet
}

// From assembles the catalog. The snapshot is the only input, so two catalogs
// built from one snapshot cannot differ.
func From(snap store.Fleet) Catalog {
	c := Catalog{byID: map[string]int{}, vms: map[string][]store.Instance{}, snap: snap}

	declared := make(map[string]store.Deployment, len(snap.Deployments))
	for _, d := range snap.Deployments {
		declared[d.ID] = d
	}
	index := func(id string) *Farm {
		if i, ok := c.byID[id]; ok {
			return &c.farms[i]
		}
		f := Farm{ID: id}
		if d, ok := declared[id]; ok {
			f.Name, f.Region, f.State = d.DisplayName, d.Region, d.State
		}
		c.byID[id] = len(c.farms)
		c.farms = append(c.farms, f)
		return &c.farms[len(c.farms)-1]
	}

	// A deployment somebody named before anything was ever probed is still a
	// deployment. Leaving it out would make `farm name` appear to do nothing.
	for _, d := range snap.Deployments {
		index(d.ID)
	}
	for _, h := range snap.Hosts {
		// Membership, not detection alone: a host that runs OpenStack and that
		// nothing has claimed belongs to no deployment, and inventing one from
		// what it runs is the mistake this schema was shaped to avoid.
		if h.Farm == "" || !h.Detected {
			continue
		}
		f := index(h.Farm)
		f.Hosts = append(f.Hosts, h)
		if h.Confidence == store.ConfidenceLocalOnly {
			f.Unsettled++
		}
	}
	// The counts are read as counts, so a deployment that has only VMs — no
	// probed host, nothing declared — still appears.
	for id := range snap.VMs {
		index(id)
	}
	for id := range snap.Gone {
		index(id)
	}
	for _, v := range snap.Instances {
		index(v.DeploymentID)
		if v.MissingSince != nil {
			continue
		}
		c.vms[v.DeploymentID] = append(c.vms[v.DeploymentID], v)
	}
	// By what is printed, so the order on screen looks like an order. Sorting
	// on the endpoint while showing the name produced "incheon, seoul-b,
	// 172.16.0.21, seoul-a" — correct, and looking like no order at all.
	sort.SliceStable(c.farms, func(i, j int) bool {
		return c.farms[i].Label() < c.farms[j].Label()
	})
	for i, f := range c.farms {
		c.byID[f.ID] = i
	}
	return c
}

// Farms is every deployment, in the order they are shown.
func (c Catalog) Farms() []Farm { return c.farms }

// VMs is what the control plane still lists for this deployment.
//
// Only the full reading has the rows; the light one carries counts alone, so
// this is empty there and VMCount is what to ask. That is why they are on the
// catalog rather than on the farm: the caller has to name which one it wants,
// and the one that is always right is the count.
func (c Catalog) VMs(farmID string) []store.Instance { return c.vms[farmID] }

// AllVMs is every instance row in the reading, in the order the database
// returned them and including the ones the control plane has stopped listing.
//
// Deliberately not the per-farm lists concatenated. Those have already dropped
// the missing rows, and joining them back together would follow map order
// rather than the deployment order the rows arrived in — so a caller wanting
// the whole fleet takes the rows as they came.
func (c Catalog) AllVMs() []store.Instance { return c.snap.Instances }

// VMCount is how many VMs the control plane still lists, from either reading.
func (c Catalog) VMCount(farmID string) int { return c.snap.VMs[farmID] }

// Gone counts the VMs the control plane has stopped listing — a different fact
// from a smaller VMCount, and one an assessment needs.
func (c Catalog) Gone(farmID string) int { return c.snap.Gone[farmID] }

// Reconciled is when a reconcile last settled this deployment, and whether one
// ever has. "Never" is a different statement from "a long time ago".
func (c Catalog) Reconciled(farmID string) (time.Time, bool) {
	run, ok := c.snap.Runs[farmID]
	if !ok || run.SucceededAt == nil {
		return time.Time{}, false
	}
	return *run.SucceededAt, true
}

// Run is the last reconcile recorded for a deployment, or nil.
func (c Catalog) Run(farmID string) *store.ReconcileRun {
	run, ok := c.snap.Runs[farmID]
	if !ok {
		return nil
	}
	return &run
}

// Find returns the deployment with this exact id.
func (c Catalog) Find(id string) (Farm, bool) {
	i, ok := c.byID[id]
	if !ok {
		return Farm{}, false
	}
	return c.farms[i], true
}

// Hosts is every host a probe has reported on, including the ones it found no
// OpenStack on and the ones no deployment has claimed. The listing needs those;
// a farm cannot hold them.
func (c Catalog) Hosts() []store.OpenStackHost { return c.snap.Hosts }

// Instances is every VM, including the ones the control plane has stopped
// listing — Farm.VMs is the filtered view.
func (c Catalog) Instances() []store.Instance { return c.snap.Instances }

// Deployments is the declared rows as they are stored.
func (c Catalog) Deployments() []store.Deployment { return c.snap.Deployments }

// Names maps deployment id to display name, for renderers that hold ids and
// print labels.
func (c Catalog) Names() map[string]string {
	out := make(map[string]string, len(c.farms))
	for _, f := range c.farms {
		if f.Name != "" {
			out[f.ID] = f.Name
		}
	}
	return out
}

// ReadAt is when the database took the snapshot every answer here comes from.
func (c Catalog) ReadAt() time.Time { return c.snap.ReadAt }

// InventoryHosts is the fleet the probed hosts are a fraction of.
func (c Catalog) InventoryHosts() int { return c.snap.InventoryHosts }

// Resolve turns what somebody typed into exactly one deployment.
//
// Every command that takes a deployment goes through here, because the rules
// only mean anything if they are the same everywhere. They were not: the
// listing matched ids and membership ids and never the name on screen, so
// `--farm seoul-b` — the name that listing itself prints — returned nothing and
// rendered it as an empty fleet.
//
// The rules:
//
//   - An exact id wins outright. It is the identifier; nothing overrides it,
//     including another deployment that happens to be *named* that.
//   - A display name is accepted only when it belongs to one deployment.
//   - Two deployments sharing a name is not something to resolve by position.
//     `farm state` and `farm name` change things, and picking whichever sorted
//     first would change the wrong one silently. Both ids are printed and the
//     command stops.
//   - A selector that matches nothing is an error. An empty listing looks like
//     an answer, and "this farm has no hosts" is a very different sentence from
//     "there is no such farm".
func (c Catalog) Resolve(selector string) (Farm, error) { return Resolve(c.farms, selector) }

// Resolve is the same rule over a plain list, for callers holding the farms
// rather than the catalog they came from. One implementation, because a second
// copy of these rules is exactly what this package exists to remove.
func Resolve(farms []Farm, selector string) (Farm, error) {
	if strings.TrimSpace(selector) == "" {
		return Farm{}, fmt.Errorf("a deployment is required")
	}
	for _, f := range farms {
		if strings.EqualFold(f.ID, selector) {
			return f, nil
		}
	}
	var byName []Farm
	for _, f := range farms {
		if f.Name != "" && strings.EqualFold(f.Name, selector) {
			byName = append(byName, f)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return Farm{}, fmt.Errorf("no deployment %q; run 'vctl openstack' to see them", selector)
	default:
		ids := make([]string, 0, len(byName))
		for _, f := range byName {
			ids = append(ids, f.ID)
		}
		return Farm{}, fmt.Errorf("%q names %d deployments (%s); use the id",
			selector, len(byName), strings.Join(ids, ", "))
	}
}

// IndexOf is Resolve for callers that need a position in Farms(), such as a
// picker's starting cursor. -1 when the selector does not resolve.
func (c Catalog) IndexOf(selector string) int { return IndexOf(c.farms, selector) }

// IndexOf is Resolve as a position in the list it was given.
func IndexOf(farms []Farm, selector string) int {
	got, err := Resolve(farms, selector)
	if err != nil {
		return -1
	}
	for i, f := range farms {
		if f.ID == got.ID {
			return i
		}
	}
	return -1
}
