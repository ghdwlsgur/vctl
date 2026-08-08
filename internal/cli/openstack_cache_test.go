package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// appWithStoredReading is an app whose cache holds one reading and whose
// database is a port nothing is listening on.
//
// The unreachable DSN is the test: any path that goes to the database fails
// loudly instead of quietly returning the same rows from somewhere else.
func appWithStoredReading(t *testing.T, shape fleet.Shape, at time.Time) *app.App {
	t.Helper()
	a := &app.App{Cfg: &config.Config{
		StateDir:   t.TempDir(),
		LocalDBDSN: "postgres://nobody@127.0.0.1:1/none?sslmode=disable",
	}}
	gone := at.Add(-time.Hour)
	snap := store.Fleet{
		Deployments: []store.Deployment{
			{ID: "10.0.0.1:5000", DisplayName: "seoul-a"},
			{ID: "10.0.0.2:5000", DisplayName: "seoul-b"},
		},
		Hosts: []store.OpenStackHost{
			{Hostname: "sre-srv-0001", Farm: "10.0.0.1:5000", Detected: true, Roles: []string{"compute"}},
			{Hostname: "sre-srv-0009", Farm: "10.0.0.2:5000", Detected: true, Roles: []string{"compute"}},
		},
		// In the order instancesOn returns them: deployment, name, instance id.
		Instances: []store.Instance{
			{DeploymentID: "10.0.0.1:5000", InstanceID: "u-1", Name: "bastion", Status: "ACTIVE"},
			{DeploymentID: "10.0.0.1:5000", InstanceID: "u-2", Name: "quay", Status: "ACTIVE"},
			{DeploymentID: "10.0.0.1:5000", InstanceID: "u-3", Name: "retired", MissingSince: &gone},
			{DeploymentID: "10.0.0.2:5000", InstanceID: "u-9", Name: "worker-1", Status: "ACTIVE"},
		},
		VMs:            map[string]int{"10.0.0.1:5000": 2, "10.0.0.2:5000": 1},
		Gone:           map[string]int{"10.0.0.1:5000": 1},
		InventoryHosts: 44,
		ReadAt:         at,
	}
	if err := a.FleetCache().Save(shape, snap); err != nil {
		t.Fatalf("save: %v", err)
	}
	return a
}

// A fresh stored reading answers a listing without a database.
func TestAListingIsServedFromTheStoredReadingWhenItIsFresh(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeFarms, time.Now().Add(-time.Minute))
	st := &openLater{app: a}
	defer st.Close()

	cat, err := listingCatalog(context.Background(), a, st, false, loadFarmCatalog)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if got := len(cat.Farms()); got != 2 {
		t.Fatalf("%d farms from the stored reading", got)
	}
	if cat.InventoryHosts() != 44 {
		t.Errorf("coverage denominator lost: %d", cat.InventoryHosts())
	}
}

// Past the fresh window it goes to the database instead of serving something
// nobody was told the age of.
//
// UsableFor is the browser's window, not a listing's: the browser corrects
// itself a second later and a command that prints once and exits does not.
func TestAListingPastTheFreshWindowReadsTheDatabase(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeFarms, time.Now().Add(-fleet.FreshFor-time.Minute))
	st := &openLater{app: a}
	defer st.Close()

	if _, err := listingCatalog(context.Background(), a, st, false, loadFarmCatalog); err == nil {
		t.Error("a reading older than the fresh window was served anyway")
	}
}

// --fresh and --json both mean the database. --json is not a preference: the
// note saying how old an answer is goes to stderr for a person, and a program
// parsing stdout cannot see it.
func TestJSONAndFreshBothRefuseTheStoredReading(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeFarms, time.Now())
	st := &openLater{app: a}
	defer st.Close()

	if _, err := listingCatalog(context.Background(), a, st, true, loadFarmCatalog); err == nil {
		t.Error("a run that asked for the database was answered from disk")
	}

	root := NewRoot(Dependencies{})
	cmd, _, err := root.Find([]string{"openstack", "farm", "list"})
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	// ParseFlags is what cobra does before RunE, and it is what merges the
	// persistent --fresh down from `openstack`. Asking before that would be
	// asking a question the command never faces.
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !mustBeLive(cmd, true) {
		t.Error("--json does not force a live read")
	}
	if mustBeLive(cmd, false) {
		t.Error("a plain run refuses the stored reading")
	}
	if err := cmd.ParseFlags([]string{"--fresh"}); err != nil {
		t.Fatalf("parse --fresh: %v", err)
	}
	if !mustBeLive(cmd, false) {
		t.Error("--fresh does not force a live read")
	}
}

// --fresh is one flag on `openstack`, so it means the same thing on every
// listing under it. Registering it per command is how they drift.
func TestFreshIsAvailableOnEveryListingUnderOpenstack(t *testing.T) {
	root := NewRoot(Dependencies{})
	for _, path := range [][]string{
		{"openstack"},
		{"openstack", "vm"},
		{"openstack", "farm", "list"},
		{"openstack", "explore"},
	} {
		cmd, _, err := root.Find(path)
		if err != nil {
			t.Fatalf("%v: %v", path, err)
		}
		if err := cmd.ParseFlags([]string{"--fresh"}); err != nil {
			t.Errorf("%s does not take --fresh: %v", strings.Join(path, " "), err)
			continue
		}
		if !wantsFresh(cmd) {
			t.Errorf("%s parsed --fresh and did not see it", strings.Join(path, " "))
		}
	}
}

// The VM listing from a stored reading has to be what the database would have
// returned: the same two predicates, in the same order.
func TestTheVMProjectionReproducesTheQueryItStandsInFor(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeVMs, time.Now())
	cat, _, ok := storedCatalog(a, fleet.ShapeVMs, fleet.FreshFor)
	if !ok {
		t.Fatal("the stored reading was not served")
	}

	all, err := vmsFrom(cat, "", false)
	if err != nil {
		t.Fatalf("storedVMs: %v", err)
	}
	if got := vmNames(all); strings.Join(got, ",") != "bastion,quay,worker-1" {
		t.Errorf("whole fleet = %v; wrong rows or wrong order", got)
	}

	// --missing brings back what the control plane stopped listing. The
	// catalog's per-farm lists have already dropped those, so going through
	// them would make this silently empty.
	withGone, err := vmsFrom(cat, "", true)
	if err != nil {
		t.Fatalf("storedVMs: %v", err)
	}
	if got := vmNames(withGone); strings.Join(got, ",") != "bastion,quay,retired,worker-1" {
		t.Errorf("--missing = %v; the deleted VM is not in it", got)
	}

	// And --farm narrows to the deployment, by the name the listing prints.
	one, err := vmsFrom(cat, "seoul-b", false)
	if err != nil {
		t.Fatalf("storedVMs: %v", err)
	}
	if got := vmNames(one); strings.Join(got, ",") != "worker-1" {
		t.Errorf("--farm seoul-b = %v", got)
	}

	// A deployment nobody has heard of is an error, not an empty listing.
	if _, err := vmsFrom(cat, "nowhere", false); err == nil {
		t.Error("an unknown deployment produced an empty list instead of an error")
	}
}

// A farms reading has no instance rows, so it must not answer a VM listing —
// an empty list there reads as a deployment with nothing in it.
func TestAVMListingIsNotServedFromAFarmsReading(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeFarms, time.Now())
	if _, _, ok := storedCatalog(a, fleet.ShapeVMs, fleet.FreshFor); ok {
		t.Error("a farms reading answered a request for VM rows")
	}
	if _, _, ok := storedCatalog(a, fleet.ShapeFarms, fleet.FreshFor); !ok {
		t.Error("and it did not answer the request it can answer")
	}
}

// A Tab reads the stored list and nothing else.
//
// This is the completion pressed most and the one that most often came back
// empty: the budget is two seconds and the first contact with Vault and
// Postgres after an idle period takes about ten, so it was paying for an answer
// it then abandoned.
func TestFarmCompletionAnswersFromDiskWithoutADatabase(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeFarms, time.Now().Add(-2*time.Hour))
	env := CommandEnv{NewApp: func() (*app.App, error) { return a, nil }}

	got, directive := completeFarm(env, unassignedFarm)(nil, nil, "seoul")
	if directive != 4 && len(got) == 0 {
		t.Fatalf("no candidates: %v", got)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{"seoul-a", "seoul-b"} {
		if !strings.Contains(joined, want) {
			t.Errorf("candidates %v do not offer %q", got, want)
		}
	}

	// Two hours old is past a listing's window and well inside a Tab's. A Tab is
	// not a decision — the worst a stale list does is fail to offer a farm
	// somebody renamed this morning, and typing it still works.
	if _, _, ok := storedCatalog(a, fleet.ShapeFarms, fleet.FreshFor); ok {
		t.Error("the fixture is fresh enough for a listing; this test is not proving anything")
	}
}

func vmNames(vms []store.Instance) []string {
	out := make([]string, 0, len(vms))
	for _, v := range vms {
		out = append(out, v.Name)
	}
	return out
}
