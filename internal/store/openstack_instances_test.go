package store

import (
	"context"
	"testing"
	"time"
)

func seedInstanceFarm(t *testing.T, st *Store, id string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO openstack_deployments (id) VALUES ($1) ON CONFLICT (id) DO NOTHING`, id); err != nil {
		t.Fatalf("seed deployment: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_instances WHERE deployment_id=$1`, id)
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_deployments WHERE id=$1`, id)
	})
}

func vm(id, name, hyper string, addrs ...InstanceAddress) Instance {
	return Instance{
		InstanceID: id, Name: name, Status: "ACTIVE", PowerState: "running",
		HypervisorHostname: hyper, Addresses: addrs,
	}
}

// A VM round-trips with the two joins the chain rests on: the hypervisor it
// sits on, and the UUID Kubernetes names it by.
// Integration — needs VCTL_TEST_DSN.
func TestInstancesRoundTripWithAddresses(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "vm-farm-a"
	seedInstanceFarm(t, st, farm)

	in := vm("uuid-1", "k8s-worker-1", "gpu01",
		InstanceAddress{NetworkName: "internal", Address: "10.0.0.5", Type: "fixed", IPVersion: 4},
		InstanceAddress{NetworkName: "external", Address: "192.0.2.9", Type: "floating", IPVersion: 4})
	if _, err := st.ReplaceInstances(ctx, farm, []Instance{in}, time.Now(), true); err != nil {
		t.Fatalf("ReplaceInstances: %v", err)
	}

	got, err := st.Instances(ctx, InstanceFilter{DeploymentID: farm})
	if err != nil || len(got) != 1 {
		t.Fatalf("Instances: %v (%d rows)", err, len(got))
	}
	if got[0].HypervisorHostname != "gpu01" {
		t.Errorf("hypervisor = %q — the join to the physical host", got[0].HypervisorHostname)
	}
	if len(got[0].Addresses) != 2 {
		t.Errorf("addresses = %+v, want both", got[0].Addresses)
	}
}

// The Kubernetes join arrives with a bare UUID and no deployment: a node's
// providerID is openstack:///<uuid> and nothing else.
// Integration — needs VCTL_TEST_DSN.
func TestInstancesFoundByUUIDAlone(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "vm-farm-b"
	seedInstanceFarm(t, st, farm)

	if _, err := st.ReplaceInstances(ctx, farm, []Instance{vm("uuid-k8s", "node-1", "gpu02")}, time.Now(), true); err != nil {
		t.Fatalf("ReplaceInstances: %v", err)
	}
	got, err := st.Instances(ctx, InstanceFilter{InstanceID: "uuid-k8s"})
	if err != nil || len(got) != 1 {
		t.Fatalf("lookup by uuid alone: %v (%d rows)", err, len(got))
	}
}

// "which VM has this IP" is asked while somebody is looking at a connection
// log, which is why addresses are a table and not a JSON column.
// Integration — needs VCTL_TEST_DSN.
func TestInstancesFoundByAddress(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "vm-farm-c"
	seedInstanceFarm(t, st, farm)

	if _, err := st.ReplaceInstances(ctx, farm, []Instance{
		vm("uuid-2", "db-1", "gpu03", InstanceAddress{Address: "10.9.9.9", Type: "fixed", IPVersion: 4}),
	}, time.Now(), true); err != nil {
		t.Fatalf("ReplaceInstances: %v", err)
	}
	got, err := st.Instances(ctx, InstanceFilter{Address: "10.9.9.9"})
	if err != nil || len(got) != 1 || got[0].Name != "db-1" {
		t.Fatalf("lookup by address: %v (%d rows)", err, len(got))
	}
}

// A VM missing from one listing is marked, not deleted. The row is the only
// record that the machine ever existed, and that is exactly what somebody asks
// about after an incident.
// Integration — needs VCTL_TEST_DSN.
func TestInstancesMarkAbsenceInsteadOfDeleting(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "vm-farm-d"
	seedInstanceFarm(t, st, farm)

	if _, err := st.ReplaceInstances(ctx, farm, []Instance{
		vm("uuid-3", "keeps", "gpu04"), vm("uuid-4", "goes", "gpu04"),
	}, time.Now().Add(-time.Hour), true); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := st.ReplaceInstances(ctx, farm, []Instance{vm("uuid-3", "keeps", "gpu04")}, time.Now(), true); err != nil {
		t.Fatalf("second: %v", err)
	}

	live, _ := st.Instances(ctx, InstanceFilter{DeploymentID: farm})
	if len(live) != 1 || live[0].InstanceID != "uuid-3" {
		t.Errorf("live listing = %+v, want only the one still there", live)
	}
	all, _ := st.Instances(ctx, InstanceFilter{DeploymentID: farm, IncludeMissing: true})
	if len(all) != 2 {
		t.Fatalf("with --missing = %d rows, want the gone VM kept", len(all))
	}
	for _, i := range all {
		if i.InstanceID == "uuid-4" && i.MissingSince == nil {
			t.Error("the absent VM was not stamped")
		}
	}
}

// A VM that comes back stops being missing, so the column always means
// "missing now" rather than "was missing once".
// Integration — needs VCTL_TEST_DSN.
func TestInstanceReturningClearsMissing(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "vm-farm-e"
	seedInstanceFarm(t, st, farm)

	one := []Instance{vm("uuid-5", "flaps", "gpu05")}
	if _, err := st.ReplaceInstances(ctx, farm, one, time.Now().Add(-2*time.Hour), true); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := st.ReplaceInstances(ctx, farm, nil, time.Now().Add(-time.Hour), true); err != nil {
		t.Fatalf("absent pass: %v", err)
	}
	if _, err := st.ReplaceInstances(ctx, farm, one, time.Now(), true); err != nil {
		t.Fatalf("return pass: %v", err)
	}

	got, _ := st.Instances(ctx, InstanceFilter{DeploymentID: farm})
	if len(got) != 1 || got[0].MissingSince != nil {
		t.Errorf("a returned VM is still marked missing: %+v", got)
	}
}

// The physical-host join uses nova's name, and the names are re-derived rather
// than stored resolved — so the listing has to offer them.
// Integration — needs VCTL_TEST_DSN.
func TestHypervisorNamesAreListed(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "vm-farm-f"
	seedInstanceFarm(t, st, farm)

	if _, err := st.ReplaceInstances(ctx, farm, []Instance{
		vm("uuid-6", "a", "aio01"), vm("uuid-7", "b", "aio01"), vm("uuid-8", "c", "gpu01"),
	}, time.Now(), true); err != nil {
		t.Fatalf("ReplaceInstances: %v", err)
	}
	names, err := st.HypervisorNames(ctx, farm)
	if err != nil {
		t.Fatalf("HypervisorNames: %v", err)
	}
	if len(names) != 2 {
		t.Errorf("names = %v, want each host once", names)
	}
}

// A listing that stopped early must not take the rest of the deployment with
// it.
//
// The collector stores what a truncated pass did reach — those rows are current
// and worth having. What it must not do is let the store read everything past
// that prefix as gone: an API answering half a question would render as a
// deployment that lost half its VMs, and once written the two are the same row.
//
// Same rule the host membership already follows on a partial control-plane
// answer (ReconcileInput.Complete): hold, do not demote.
// Integration — needs VCTL_TEST_DSN.
func TestAPartialListingDoesNotMarkTheRestMissing(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "vm-farm-partial"
	seedInstanceFarm(t, st, farm)

	full := []Instance{
		vm("uuid-p1", "one", "gpu01"),
		vm("uuid-p2", "two", "gpu01"),
		vm("uuid-p3", "three", "gpu01"),
	}
	if _, err := st.ReplaceInstances(ctx, farm, full, time.Now().Add(-time.Hour), true); err != nil {
		t.Fatalf("first pass: %v", err)
	}

	// The next pass reaches only the first VM and says so.
	if _, err := st.ReplaceInstances(ctx, farm, full[:1], time.Now(), false); err != nil {
		t.Fatalf("partial pass: %v", err)
	}

	rows, err := st.Instances(ctx, InstanceFilter{DeploymentID: farm, IncludeMissing: true})
	if err != nil {
		t.Fatalf("Instances: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d VMs, want all three still recorded", len(rows))
	}
	for _, r := range rows {
		if r.MissingSince != nil {
			t.Errorf("%s was marked missing by a pass that never claimed to be whole", r.InstanceID)
		}
	}
}

// A whole listing still retires what it did not name — that is the behaviour the
// column exists for, and the partial case must not have disabled it.
// Integration — needs VCTL_TEST_DSN.
func TestACompleteListingStillMarksAbsentVMsMissing(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "vm-farm-complete"
	seedInstanceFarm(t, st, farm)

	full := []Instance{vm("uuid-c1", "stays", "gpu01"), vm("uuid-c2", "leaves", "gpu01")}
	if _, err := st.ReplaceInstances(ctx, farm, full, time.Now().Add(-time.Hour), true); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	if _, err := st.ReplaceInstances(ctx, farm, full[:1], time.Now(), true); err != nil {
		t.Fatalf("second pass: %v", err)
	}

	rows, err := st.Instances(ctx, InstanceFilter{DeploymentID: farm, IncludeMissing: true})
	if err != nil {
		t.Fatalf("Instances: %v", err)
	}
	var gone int
	for _, r := range rows {
		if r.MissingSince != nil {
			gone++
			if r.InstanceID != "uuid-c2" {
				t.Errorf("%s was retired but the control plane still lists it", r.InstanceID)
			}
		}
	}
	if gone != 1 {
		t.Errorf("%d VMs marked missing, want the one the deployment stopped listing", gone)
	}
}

// A Nova uuid is the identity inside a deployment, not across the fleet — the
// table is keyed (deployment_id, instance_id) and says so.
//
// The address lookup keyed on the uuid alone, which contradicted that: the same
// uuid in two deployments had both farms' addresses merged onto each row. A
// connection made from that list could reach the other farm's machine, and
// nothing on screen would have distinguished the two.
// Integration — needs VCTL_TEST_DSN.
func TestAddressesDoNotCrossDeployments(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const a, b = "vm-farm-x", "vm-farm-y"
	const shared = "uuid-shared"
	seedInstanceFarm(t, st, a)
	seedInstanceFarm(t, st, b)

	withAddr := func(id, name, addr string) Instance {
		v := vm(id, name, "gpu01")
		v.Addresses = []InstanceAddress{{NetworkName: "tenant", Address: addr, Type: "fixed", IPVersion: 4}}
		return v
	}
	if _, err := st.ReplaceInstances(ctx, a, []Instance{withAddr(shared, "in-a", "10.3.1.7")}, time.Now(), true); err != nil {
		t.Fatalf("farm a: %v", err)
	}
	if _, err := st.ReplaceInstances(ctx, b, []Instance{withAddr(shared, "in-b", "10.9.9.9")}, time.Now(), true); err != nil {
		t.Fatalf("farm b: %v", err)
	}

	for _, tc := range []struct{ farm, want string }{{a, "10.3.1.7"}, {b, "10.9.9.9"}} {
		rows, err := st.Instances(ctx, InstanceFilter{DeploymentID: tc.farm, InstanceID: shared})
		if err != nil {
			t.Fatalf("Instances(%s): %v", tc.farm, err)
		}
		if len(rows) != 1 {
			t.Fatalf("%s: got %d rows, want one", tc.farm, len(rows))
		}
		if n := len(rows[0].Addresses); n != 1 {
			t.Errorf("%s: %d addresses, want only its own: %+v", tc.farm, n, rows[0].Addresses)
			continue
		}
		if got := rows[0].Addresses[0].Address; got != tc.want {
			t.Errorf("%s: address = %s, want %s", tc.farm, got, tc.want)
		}
	}
}

// Projects is what turns the name in the table into something --project
// accepts, so the set it returns has to be the set the rows carry.
// Integration — needs VCTL_TEST_DSN.
func TestProjectsAndFilteringByMoreThanOneOfThem(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farmA, farmB = "proj-farm-a", "proj-farm-b"
	seedInstanceFarm(t, st, farmA)
	seedInstanceFarm(t, st, farmB)

	withProject := func(v Instance, id, name string) Instance {
		v.ProjectID, v.ProjectName = id, name
		return v
	}
	now := time.Now()
	if _, err := st.ReplaceInstances(ctx, farmA, []Instance{
		withProject(vm("p-1", "one", "h1"), "aaa", "admin"),
		withProject(vm("p-2", "two", "h1"), "ccc", "platform"),
	}, now, true); err != nil {
		t.Fatalf("ReplaceInstances farmA: %v", err)
	}
	// The same *name* in another farm, on a different project id — the case
	// that makes --project by name ambiguous in the first place.
	if _, err := st.ReplaceInstances(ctx, farmB, []Instance{
		withProject(vm("p-3", "three", "h2"), "bbb", "admin"),
	}, now, true); err != nil {
		t.Fatalf("ReplaceInstances farmB: %v", err)
	}

	seen := map[string]Project{}
	all, err := st.Projects(ctx, "")
	if err != nil {
		t.Fatalf("Projects: %v", err)
	}
	for _, p := range all {
		if p.DeploymentID == farmA || p.DeploymentID == farmB {
			seen[p.ID] = p
		}
	}
	if len(seen) != 3 {
		t.Fatalf("got %d projects across the two farms, want 3: %v", len(seen), seen)
	}
	if p := seen["aaa"]; p.Name != "admin" || p.VMs != 1 {
		t.Errorf("aaa = %+v, want admin with 1 VM", p)
	}
	if p := seen["bbb"]; p.DeploymentID != farmB {
		t.Errorf("bbb is in %q, want %q — a name is per-deployment", p.DeploymentID, farmB)
	}

	only, err := st.Projects(ctx, farmB)
	if err != nil {
		t.Fatalf("Projects(farmB): %v", err)
	}
	if len(only) != 1 || only[0].ID != "bbb" {
		t.Fatalf("Projects(farmB) = %+v, want just bbb", only)
	}

	// Both admins at once: what resolving the name "admin" without --farm
	// produces.
	vms, err := st.Instances(ctx, InstanceFilter{ProjectIDs: []string{"aaa", "bbb"}})
	if err != nil {
		t.Fatalf("Instances by project: %v", err)
	}
	if len(vms) != 2 {
		t.Fatalf("got %d VMs, want the one in each farm", len(vms))
	}
	for _, v := range vms {
		if v.ProjectName != "admin" {
			t.Errorf("%s is in project %q", v.InstanceID, v.ProjectName)
		}
	}

	one, err := st.Instances(ctx, InstanceFilter{ProjectIDs: []string{"ccc"}})
	if err != nil || len(one) != 1 || one[0].InstanceID != "p-2" {
		t.Fatalf("single project filter = %+v (%v)", one, err)
	}
}
