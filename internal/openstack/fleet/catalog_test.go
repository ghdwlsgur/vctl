package fleet

import (
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func host(name, farm string, roles ...string) store.OpenStackHost {
	return store.OpenStackHost{
		Hostname: name, Farm: farm, Detected: true, Roles: roles,
		Confidence: store.ConfidenceConfirmed,
	}
}

func vm(id, farm, name string) store.Instance {
	return store.Instance{InstanceID: id, DeploymentID: farm, Name: name, Status: "ACTIVE"}
}

func testSnapshot() store.Fleet {
	at := time.Now().Add(-30 * time.Minute)
	gone := time.Now().Add(-3 * time.Hour)
	missing := vm("v-gone", "10.0.0.1:5000", "deleted")
	missing.MissingSince = &gone
	local := host("sre-srv-0003", "10.0.0.1:5000", "compute")
	local.Confidence = store.ConfidenceLocalOnly
	return store.Fleet{
		Deployments: []store.Deployment{
			{ID: "10.0.0.1:5000", DisplayName: "seoul-a", Region: "kr", State: store.StateActive},
			{ID: "10.0.0.2:5000", DisplayName: "seoul-b", State: store.StateRetired},
			// Named before anything probed it: no hosts, no VMs, still a farm.
			{ID: "10.0.0.9:5000", DisplayName: "brand-new", State: store.StateActive},
		},
		Hosts: []store.OpenStackHost{
			host("sre-srv-0001", "10.0.0.1:5000", "controller"),
			host("sre-srv-0002", "10.0.0.1:5000", "compute"),
			local,
			host("sre-srv-0008", "10.0.0.2:5000", "compute"),
			// Runs OpenStack, nothing has claimed it.
			host("sre-srv-0020", ""),
			// Probed and found nothing.
			{Hostname: "sre-srv-0030", Detected: false},
		},
		Instances: []store.Instance{
			vm("v-1", "10.0.0.1:5000", "bastion"),
			vm("v-2", "10.0.0.1:5000", "worker"),
			missing,
			vm("v-8", "10.0.0.2:5000", "old-thing"),
		},
		VMs:            map[string]int{"10.0.0.1:5000": 2, "10.0.0.2:5000": 1},
		Gone:           map[string]int{"10.0.0.1:5000": 1},
		Runs:           map[string]store.ReconcileRun{"10.0.0.1:5000": {SucceededAt: &at}},
		InventoryHosts: 40,
		ReadAt:         time.Now(),
	}
}

// The counts are the reason four commands were assembling this separately, and
// the reason they could disagree.
func TestCatalogGathersEachDeploymentsHostsAndVMs(t *testing.T) {
	c := From(testSnapshot())
	f, ok := c.Find("10.0.0.1:5000")
	if !ok {
		t.Fatal("seoul-a is missing")
	}
	if len(f.Hosts) != 3 {
		t.Errorf("hosts = %d, want 3", len(f.Hosts))
	}
	if got := c.VMs(f.ID); len(got) != 2 {
		t.Errorf("live VMs = %d, want 2", len(got))
	}
	// Gone is a different fact, not a smaller count of the same one.
	if c.Gone(f.ID) != 1 {
		t.Errorf("gone = %d, want the one the control plane stopped listing", c.Gone(f.ID))
	}
	if f.Unsettled != 1 {
		t.Errorf("unsettled = %d, want the local-only host", f.Unsettled)
	}
	if at, ok := c.Reconciled(f.ID); !ok || time.Since(at) > time.Hour {
		t.Errorf("reconciled at %v (ok=%v)", at, ok)
	}
	if counts := f.RoleCounts(); counts["compute"] != 2 || counts["controller"] != 1 {
		t.Errorf("role counts = %v", counts)
	}
}

// A host nothing has claimed belongs to no deployment. Placing it by what it
// runs is the inference the schema exists to refuse.
func TestCatalogLeavesUnclaimedAndUndetectedHostsOutOfEveryFarm(t *testing.T) {
	c := From(testSnapshot())
	for _, f := range c.Farms() {
		for _, h := range f.Hosts {
			if h.Hostname == "sre-srv-0020" {
				t.Errorf("an unclaimed host was placed in %s", f.ID)
			}
			if h.Hostname == "sre-srv-0030" {
				t.Errorf("a host with no OpenStack on it was placed in %s", f.ID)
			}
		}
	}
	// They are still reachable: the listing shows them, a farm cannot hold them.
	var found int
	for _, h := range c.Hosts() {
		if h.Hostname == "sre-srv-0020" || h.Hostname == "sre-srv-0030" {
			found++
		}
	}
	if found != 2 {
		t.Errorf("the listing lost %d of them", 2-found)
	}
}

// A deployment somebody named before anything probed it is still a deployment.
// Dropping it would make `farm name` look like it did nothing.
func TestCatalogKeepsADeploymentWithNothingInItYet(t *testing.T) {
	c := From(testSnapshot())
	f, ok := c.Find("10.0.0.9:5000")
	if !ok {
		t.Fatal("a named but empty deployment is missing")
	}
	if f.Name != "brand-new" || len(f.Hosts) != 0 {
		t.Errorf("got %+v", f)
	}
	if _, ok := c.Reconciled(f.ID); ok {
		t.Error("a farm nothing ever reconciled claims a reconcile time")
	}
}

// The order on screen has to look like an order. Sorting by id while showing
// the name produced "incheon, seoul-b, 172.16.0.21, seoul-a".
func TestCatalogOrdersFarmsByWhatIsPrinted(t *testing.T) {
	c := From(testSnapshot())
	var labels []string
	for _, f := range c.Farms() {
		labels = append(labels, f.Label())
	}
	for i := 1; i < len(labels); i++ {
		if labels[i-1] > labels[i] {
			t.Fatalf("out of order: %v", labels)
		}
	}
}

// The resolution rules are the reason this is one module: they were duplicated,
// and one copy matched ids only — so `--farm seoul-b`, the name that listing
// itself prints, selected nothing and rendered as an empty fleet.
func TestResolveTakesAnIDOrAUniqueName(t *testing.T) {
	c := From(testSnapshot())

	if f, err := c.Resolve("10.0.0.1:5000"); err != nil || f.Name != "seoul-a" {
		t.Errorf("by id: %+v %v", f, err)
	}
	if f, err := c.Resolve("seoul-a"); err != nil || f.ID != "10.0.0.1:5000" {
		t.Errorf("by name: %+v %v", f, err)
	}
	if f, err := c.Resolve("SEOUL-A"); err != nil || f.ID != "10.0.0.1:5000" {
		t.Errorf("case should not have to be guessed: %+v %v", f, err)
	}
	if _, err := c.Resolve("typo"); err == nil {
		t.Error("a selector matching nothing was accepted")
	} else if !strings.Contains(err.Error(), "typo") {
		t.Errorf("the error does not quote what was typed: %v", err)
	}
	if _, err := c.Resolve(""); err == nil {
		t.Error("an empty selector was accepted")
	}
}

// An id is the identifier. A deployment that happens to be *named* like another
// one's id does not take it.
func TestResolvePrefersAnIDOverANameThatCopiesIt(t *testing.T) {
	snap := testSnapshot()
	snap.Deployments = append(snap.Deployments,
		store.Deployment{ID: "10.0.0.7:5000", DisplayName: "10.0.0.1:5000"})
	c := From(snap)

	f, err := c.Resolve("10.0.0.1:5000")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if f.ID != "10.0.0.1:5000" {
		t.Errorf("resolved to %q, want the deployment whose id that is", f.ID)
	}
}

// Two deployments sharing a name is not something to resolve by position: the
// commands behind this rename and change state, and picking whichever sorted
// first would change the wrong one silently.
func TestResolveRefusesANameTwoDeploymentsShare(t *testing.T) {
	snap := testSnapshot()
	snap.Deployments = append(snap.Deployments,
		store.Deployment{ID: "10.0.0.5:5000", DisplayName: "seoul-a"})
	c := From(snap)

	_, err := c.Resolve("seoul-a")
	if err == nil {
		t.Fatal("an ambiguous name was resolved")
	}
	for _, want := range []string{"10.0.0.1:5000", "10.0.0.5:5000", "use the id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not carry %q: %v", want, err)
		}
	}
}

// IndexOf answers where a farm sits in Farms(), for a picker's starting cursor.
func TestIndexOfPointsAtThePrintedPosition(t *testing.T) {
	c := From(testSnapshot())
	i := c.IndexOf("seoul-b")
	if i < 0 {
		t.Fatal("seoul-b did not resolve")
	}
	if c.Farms()[i].Name != "seoul-b" {
		t.Errorf("index %d is %q", i, c.Farms()[i].Name)
	}
	if c.IndexOf("nothing-like-this") != -1 {
		t.Error("a selector matching nothing returned a position")
	}
}

// Retired is a declaration, and reconcile and the default listing both act on
// it. Reading it off the farm keeps the two from disagreeing about which farms
// are in service.
func TestRetiredIsReadableFromTheFarm(t *testing.T) {
	c := From(testSnapshot())
	f, _ := c.Find("10.0.0.2:5000")
	if !f.Retired() {
		t.Error("a retired deployment does not say so")
	}
	if a, _ := c.Find("10.0.0.1:5000"); a.Retired() {
		t.Error("an active deployment claims to be retired")
	}
}

// The light reading has no instances in it, and a Farm carries none — so a
// caller holding farms from it cannot ask for a VM list and be handed an empty
// one that reads as "this deployment has no VMs".
//
// The VMs live on the catalog, which only the full reading fills. That is the
// whole point of putting them there rather than on the farm.
func TestTheLightReadingCannotBeMistakenForTheFullOne(t *testing.T) {
	full := testSnapshot()
	light := store.Fleet{
		Deployments: full.Deployments, Hosts: full.Hosts,
		VMs: full.VMs, Gone: full.Gone, ReadAt: full.ReadAt,
	}

	lightCat := From(light)
	if got := len(lightCat.Farms()); got != len(From(full).Farms()) {
		t.Errorf("the two readings disagree about how many deployments there are: %d", got)
	}
	f, _ := lightCat.Find("10.0.0.1:5000")
	if len(f.Hosts) != 3 {
		t.Errorf("the light reading lost the hosts: %d", len(f.Hosts))
	}
	// Asking the light catalog for VM rows answers nothing, which is true — and
	// it has to be asked through the catalog, so the question is visible.
	if got := lightCat.VMs(f.ID); len(got) != 0 {
		t.Errorf("the light reading produced %d VM rows it never read", len(got))
	}
	// The count is there either way, which is what nearly every screen wanted.
	if got := lightCat.VMCount(f.ID); got != 2 {
		t.Errorf("the light reading lost the count: %d", got)
	}
	if lightCat.VMCount(f.ID) != From(full).VMCount(f.ID) {
		t.Error("the two readings disagree about how many VMs a deployment has")
	}
}
