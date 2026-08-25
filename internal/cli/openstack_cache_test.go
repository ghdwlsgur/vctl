package cli

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
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

	rd, err := listingReading(context.Background(), a, st, fleet.ShapeFarms, false, fleetSnapshot)
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if rd.Source != fleet.FromStored {
		t.Errorf("source = %v, want the stored reading", rd.Source)
	}
	cat := rd.Catalog
	if got := len(cat.Farms()); got != 2 {
		t.Fatalf("%d farms from the stored reading", got)
	}
	if cat.InventoryHosts() != 44 {
		t.Errorf("coverage denominator lost: %d", cat.InventoryHosts())
	}
}

// Past the fresh window it goes to the database — and when the database does
// not answer, the reading it declined a moment ago is exactly what to show.
//
// The fresh window is not the offline window. It used to be both: five minutes
// after the last successful read a listing went from instant to failed, during
// an outage, which is when somebody most wants to see what the fleet looked
// like. UsableFor is the ceiling that matters here, and the age is said out
// loud beside it.
func TestAListingPastTheFreshWindowFallsBackWhenTheDatabaseIsGone(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeFarms, time.Now().Add(-fleet.FreshFor-time.Minute))
	st := &openLater{app: a}
	defer st.Close()

	rd, err := listingReading(context.Background(), a, st, fleet.ShapeFarms, false, fleetSnapshot)
	if err != nil {
		t.Fatalf("nothing was served during an outage: %v", err)
	}
	if rd.Source != fleet.FromFallback {
		t.Errorf("source = %v, want the offline fallback", rd.Source)
	}
	// The operator is being shown an old picture and is owed the reason.
	if rd.Err == nil {
		t.Error("the fallback did not carry why the database was skipped")
	}
	if got := len(rd.Catalog.Farms()); got != 2 {
		t.Errorf("%d farms from the fallback reading", got)
	}

	// Past the usable ceiling there is nothing worth showing, and the database
	// error is the actionable fact.
	old := appWithStoredReading(t, fleet.ShapeFarms, time.Now().Add(-fleet.UsableFor-time.Hour))
	oldSt := &openLater{app: old}
	defer oldSt.Close()
	if _, err := listingReading(context.Background(), old, oldSt, fleet.ShapeFarms, false, fleetSnapshot); err == nil {
		t.Error("a day-old reading was served instead of reporting the outage")
	}
}

// --fresh and --json both mean the database. --json is not a preference: the
// note saying how old an answer is goes to stderr for a person, and a program
// parsing stdout cannot see it.
func TestJSONAndFreshBothRefuseTheStoredReading(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeFarms, time.Now())
	st := &openLater{app: a}
	defer st.Close()

	if _, err := listingReading(context.Background(), a, st, fleet.ShapeFarms, true, fleetSnapshot); err == nil {
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
		{"openstack", "list"},
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
	rd, ok := storedReader(a).Stored(fleet.ShapeVMs, fleet.ForListing)
	if !ok {
		t.Fatal("the stored reading was not served")
	}
	cat := rd.Catalog

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
	if _, ok := storedReader(a).Stored(fleet.ShapeVMs, fleet.ForListing); ok {
		t.Error("a farms reading answered a request for VM rows")
	}
	if _, ok := storedReader(a).Stored(fleet.ShapeFarms, fleet.ForListing); !ok {
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
	if _, ok := storedReader(a).Stored(fleet.ShapeFarms, fleet.ForListing); ok {
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

// The line the stored reading may not cross.
//
// Listings, pickers and completions may be answered from disk. Connecting to a
// machine, changing one, or asking a control plane about one may not — see
// fleet.Purpose for why each of those is different from looking.
//
// A guard rather than a convention, because the mistake it prevents is one
// nobody would notice making: listingCatalog is right there, it returns exactly
// the catalog a connecting path also wants, and reusing it would work perfectly
// until the day somebody was routed to an address that had been reassigned.
//
// fleet.Purpose names the same rule in the domain, and a purpose that may not
// read returns no reading rather than a stale one. That is a floor, not a
// fence: nothing makes a caller name the right purpose, so this test is still
// the enforcement.
//
// Whole files now. openstack_farm.go used to be checked function by function
// because it defined the helpers as well as the two commands forbidden to call
// them; the helpers moved to openstack_cache.go, so the exception is gone and
// the file is held to the line entirely. It still calls keepReading and
// forgetReadings — storing a reading and dropping one are not reading one.
func TestNothingThatConnectsOrChangesReadsTheStoredReading(t *testing.T) {
	readsCache := map[string]bool{
		"storedReader":   true,
		"fleetReader":    true,
		"listingReading": true,
		"vmCatalog":      true,
		"Stored":         true,
		"LoadAtLeast":    true,
		"FleetCache":     true,
	}
	// The list above is strings, which is how a guard goes quietly blind: it
	// named storedCatalog and listingCatalog for as long as those existed, and
	// the rename to fleet.Reader left it watching for two functions nobody could
	// call any more. It would have passed forever. Every local name here has to
	// still be declared in this package, so the next rename fails here.
	assertDeclaredInPackage(t, "storedReader", "fleetReader", "listingReading", "vmCatalog")
	for _, tc := range []struct{ file, what string }{
		{file: "ssh.go", what: "ssh connects to the machine it resolved"},
		{file: "openstack_reconcile.go", what: "reconcile compares what is recorded against a control plane"},
		{file: "openstack_farm_doctor.go", what: "doctor asks a farm's control plane about itself"},
		{file: "openstack_farm.go", what: "naming and declaring the state of a deployment are writes"},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, tc.file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.file, err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := ""
				switch c := call.Fun.(type) {
				case *ast.Ident:
					name = c.Name
				case *ast.SelectorExpr:
					name = c.Sel.Name
				}
				if readsCache[name] {
					t.Errorf("%s calls %s at %s; %s, and the stored reading is not what it is comparing against",
						tc.file, name, fset.Position(call.Pos()), tc.what)
				}
				return true
			})
		}
	}
}

// Changing a deployment drops the stored reading rather than editing it.
//
// The command that changed one field has not read the rest, so writing a
// partly-known picture back is how a cache starts inventing. Dropping it also
// means the next listing cannot go on showing somebody the name they just
// changed away from.
func TestChangingADeploymentDropsTheStoredReading(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeVMs, time.Now())
	// Both shapes, since a full reading answers a farms question too.
	if err := a.FleetCache().Save(fleet.ShapeFarms, store.Fleet{ReadAt: time.Now()}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, ok := storedReader(a).Stored(fleet.ShapeFarms, fleet.ForListing); !ok {
		t.Fatal("nothing stored to begin with")
	}

	forgetReadings(context.Background(), a, nil)

	for _, s := range []fleet.Shape{fleet.ShapeFarms, fleet.ShapeVMs} {
		if _, ok := storedReader(a).Stored(s, fleet.ForFallback); ok {
			t.Errorf("%s survived a change to the fleet", s)
		}
	}
	// And again on a cache that is already empty, since a rename may be the
	// first thing anybody runs.
	forgetReadings(context.Background(), a, nil)
}

// Every command that changes a deployment drops the reading. Naming and
// declaring state were added after reconcile and did not — a rename went on
// completing to the old name for a day.
func TestEveryCommandThatChangesADeploymentForgetsTheReading(t *testing.T) {
	for _, tc := range []struct{ file, fn string }{
		{"openstack_farm.go", "openstackFarmNameCmd"},
		{"openstack_farm.go", "openstackFarmStateCmd"},
		{"openstack_reconcile.go", "openstackReconcileCmd"},
	} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, tc.file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", tc.file, err)
		}
		var found bool
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != tc.fn {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "forgetReadings" {
					found = true
				}
				return true
			})
		}
		if !found {
			t.Errorf("%s changes a deployment and never calls forgetReadings", tc.fn)
		}
	}
}

// The detail view carries the freshness with it. The title bar that says it is
// not on screen there, and the detail is where a VM's addresses are — and where
// the line for reaching one is offered.
func TestTheDetailSaysHowOldTheRowsBehindItAre(t *testing.T) {
	m := testExploreModel()
	m.data.Cached = true
	m.data.ReadAt = time.Now().Add(-7 * time.Minute)
	m.focus = paneRows
	m.openDetail()

	got := ui.StripANSI(m.detailView())
	first := strings.SplitN(got, "\n", 2)[0]
	for _, want := range []string{"cached", "7m old"} {
		if !strings.Contains(first, want) {
			t.Errorf("detail header %q does not carry %q", first, want)
		}
	}
}

// Two ages, and they are not the same age.
//
// How old the reading is says when the database was last asked. How old a VM's
// record is says when the collector last saw that machine — and that is the one
// an address is only as good as. A reading taken a second ago can carry a VM
// nobody has collected for a week, so a fresh screen is not a claim that
// anything on it is current.
//
// Which is why `vctl ssh --vm` checks the second and not the first, and why a
// stored reading cannot quiet the warning.
func TestAFreshReadingDoesNotMakeAStaleVMLookCurrent(t *testing.T) {
	stale := time.Now().Add(-staleProbeWindow - time.Hour)
	v := store.Instance{
		DeploymentID: "10.0.0.1:5000", InstanceID: "u-1", Name: "bastion",
		Status: "ACTIVE", ObservedAt: stale,
		Addresses: []store.InstanceAddress{{Address: "10.10.0.5"}},
	}
	var buf bytes.Buffer
	renderVMShow(&buf, v, map[string]string{"10.0.0.1:5000": "seoul-a"}, nil, time.Now())
	if got := ui.StripANSI(buf.String()); !strings.Contains(got, "may not be current") {
		t.Errorf("a VM nobody has collected in over a window reads as current:\n%s", got)
	}

	// And the browser shows the same words, whichever side its rows came from.
	for _, cached := range []bool{false, true} {
		m := testExploreModel()
		m.data.Cached = cached
		m.data.ReadAt = time.Now()
		m.data.VMs["10.0.0.1:5000"] = []store.Instance{v}
		m.focus = paneRows
		m.openDetail()
		if got := ui.StripANSI(strings.Join(m.detail, "\n")); !strings.Contains(got, "may not be current") {
			t.Errorf("cached=%v: the browser's detail does not warn:\n%s", cached, got)
		}
	}
}

// A lapsed token no longer costs the screen.
//
// explore used to go to the database first whenever a login was due, because
// the prompt would otherwise open behind a full-screen program where nobody can
// see or answer it. That was right about the prompt and wrong about the screen:
// the reader waited for an authentication they had not asked for, to see rows
// already on disk.
//
// Now the rows go up and the refresh — the one thing needing the prompt — is
// what does not happen. This pins the half that is observable without a Vault
// fixture: what the screen says, and that r does not start a read.
func TestAScreenThatNeedsALoginSaysSoAndDoesNotRefresh(t *testing.T) {
	m := testExploreModel()
	m.data.Cached = true
	m.data.NeedsLogin = true
	m.data.ReadAt = time.Now().Add(-3 * time.Minute)
	m.refresh = func() (exploreData, error) {
		t.Error("a refresh ran; its login prompt would open behind the screen")
		return exploreData{}, nil
	}

	if got := ui.StripANSI(m.titleBar()); !strings.Contains(got, "vctl login") {
		t.Errorf("title does not say why it will not refresh: %q", got)
	}
	out, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if cmd != nil {
		t.Error("r produced a command that would prompt behind the screen")
	}
	if out.(exploreModel).refreshing {
		t.Error("the screen claims to be reading when nothing can read")
	}
	// Init must not start one either — that is the automatic path.
	if m.refreshing {
		t.Error("the screen was set up to refresh automatically")
	}
}

// A purpose that may not read gets nothing, even with a fresh reading on disk.
//
// This is the floor under the AST guard rather than a replacement for it.
// Nothing makes a connecting path name ForConnecting — it is not supposed to
// reach storedCatalog at all — but if one ever does, by whatever route, the
// answer is "no stored reading" and it goes to the database. The failure mode
// that matters here is a session opened to an address that has been reassigned,
// and returning nothing cannot cause it.
func TestAPurposeThatMayNotReadIsAnsweredWithNothing(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeFarms, time.Now())
	// The reading is there for a purpose that may read it.
	if _, ok := storedReader(a).Stored(fleet.ShapeFarms, fleet.ForListing); !ok {
		t.Fatal("nothing stored to begin with")
	}
	for _, why := range []fleet.Purpose{fleet.ForConnecting, fleet.ForChanging, fleet.ForDiagnosing} {
		if _, ok := storedReader(a).Stored(fleet.ShapeFarms, why); ok {
			t.Errorf("%s was answered from disk", why)
		}
	}
}

// assertDeclaredInPackage fails when a name the guard above watches for is no
// longer a function in this package.
//
// A guard written as a list of strings survives a rename by pointing at nothing,
// and a guard pointing at nothing passes. This is what makes the rename loud.
func assertDeclaredInPackage(t *testing.T, names ...string) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	found := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				found[fn.Name.Name] = true
			}
		}
	}
	for _, n := range names {
		if !found[n] {
			t.Errorf("the cache guard watches for %q, which is not declared in this package any more.\n"+
				"Renaming a reader without updating the guard leaves it watching for nothing, which passes.", n)
		}
	}
}

// The three listings agree about an outage.
//
// They did not. `openstack` and `farm list` served the stored reading when the
// database refused; `vm` returned the error — not by decision but because its
// copy of the same sequence stopped one branch earlier. Nobody would have
// noticed until an outage, which is the one time it matters.
//
// Stated over all three rather than for `vm` alone, because the thing worth
// holding is that they agree, not that one of them was patched.
func TestEveryListingServesTheStoredReadingDuringAnOutage(t *testing.T) {
	for _, tc := range []struct {
		name  string
		shape fleet.Shape
		load  func(context.Context, *store.Store) (store.Fleet, error)
	}{
		{"openstack", fleet.ShapeFarms, fleetSnapshot},
		{"farm list", fleet.ShapeFarms, fleetSnapshot},
		{"vm", fleet.ShapeVMs, fleetSnapshotWithVMs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Past the fresh window, so the stored reading is declined first and
			// only the outage brings it back.
			a := appWithStoredReading(t, fleet.ShapeVMs, time.Now().Add(-fleet.FreshFor-time.Minute))
			st := &openLater{app: a}
			defer st.Close()

			rd, err := listingReading(context.Background(), a, st, tc.shape, false, tc.load)
			if err != nil {
				t.Fatalf("%s reported the outage instead of showing what it had: %v", tc.name, err)
			}
			if rd.Source != fleet.FromFallback {
				t.Errorf("source = %v, want the offline fallback", rd.Source)
			}
			if got := len(rd.Catalog.Farms()); got != 2 {
				t.Errorf("%d farms from the fallback reading", got)
			}
		})
	}
}

// A VM listing served from disk carries the instance rows.
//
// The shape is the promise: asking for ShapeVMs and being handed a farms
// reading would print an empty list, which reads as a deployment somebody
// emptied rather than as a reading that never had the rows.
func TestTheVMListingFallbackStillHasItsInstances(t *testing.T) {
	a := appWithStoredReading(t, fleet.ShapeVMs, time.Now().Add(-fleet.FreshFor-time.Minute))
	st := &openLater{app: a}
	defer st.Close()

	rd, err := listingReading(context.Background(), a, st, fleet.ShapeVMs, false, fleetSnapshotWithVMs)
	if err != nil {
		t.Fatalf("vm listing during an outage: %v", err)
	}
	vms, err := vmsFrom(rd.Catalog, "", false)
	if err != nil {
		t.Fatalf("vmsFrom: %v", err)
	}
	if got := vmNames(vms); strings.Join(got, ",") != "bastion,quay,worker-1" {
		t.Errorf("fallback VM rows = %v", got)
	}
}
