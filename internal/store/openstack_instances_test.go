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
	if _, err := st.ReplaceInstances(ctx, farm, []Instance{in}, time.Now()); err != nil {
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

	if _, err := st.ReplaceInstances(ctx, farm, []Instance{vm("uuid-k8s", "node-1", "gpu02")}, time.Now()); err != nil {
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
	}, time.Now()); err != nil {
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
	}, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := st.ReplaceInstances(ctx, farm, []Instance{vm("uuid-3", "keeps", "gpu04")}, time.Now()); err != nil {
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
	if _, err := st.ReplaceInstances(ctx, farm, one, time.Now().Add(-2*time.Hour)); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := st.ReplaceInstances(ctx, farm, nil, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("absent pass: %v", err)
	}
	if _, err := st.ReplaceInstances(ctx, farm, one, time.Now()); err != nil {
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
	}, time.Now()); err != nil {
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
