package store

import (
	"context"
	"testing"
	"time"
)

func seedCapabilityHost(t *testing.T, st *Store, host string) {
	t.Helper()
	ctx := context.Background()
	_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
	if _, err := st.Insert(ctx, Server{
		Hostname: host, IP: "198.51.100.90", Port: 22, User: "rocky", DC: "test-dc", CARole: "sre-core",
	}); err != nil {
		t.Fatalf("insert %s: %v", host, err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM server_capabilities WHERE hostname=$1`, host)
		_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
	})
}

// A capability round-trips with its per-component versions intact.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityRoundTrips(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-01"
	seedCapabilityHost(t, st, host)

	at := time.Now().Truncate(time.Second)
	in := Capability{
		Hostname: host, Kind: "openstack", Role: "compute", Detected: true,
		Components: map[string]CapabilityComponent{
			"nova-compute": {Version: "31.2.0", Active: true},
			"libvirt":      {Version: "10.0.0", Active: true},
			"qemu":         {Version: "8.2.0"},
		},
		Details:    map[string]string{"hypervisor": "kvm", "deployment": "unknown"},
		ObservedAt: at,
	}
	ok, err := st.UpsertCapability(ctx, in)
	if err != nil || !ok {
		t.Fatalf("UpsertCapability: %v ok=%v", err, ok)
	}

	rows, err := st.Capabilities(ctx, "openstack")
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	var got *Capability
	for i := range rows {
		if rows[i].Hostname == host {
			got = &rows[i]
		}
	}
	if got == nil {
		t.Fatalf("%s not in the listing", host)
	}
	// Per component, because a rolling upgrade leaves them apart for weeks and a
	// single release string could not say which one lagged.
	if got.Components["nova-compute"].Version != "31.2.0" || got.Components["qemu"].Version != "8.2.0" {
		t.Errorf("component versions lost: %+v", got.Components)
	}
	if got.Details["hypervisor"] != "kvm" {
		t.Errorf("details lost: %+v", got.Details)
	}
	if !got.Detected {
		t.Error("detected did not survive")
	}
}

// The write refuses to create inventory, the same way the heartbeat does. A host
// that could file capabilities for a name it does not own could invent a compute
// node, and anything planning maintenance from this would believe it.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityRefusesAnUnknownHost(t *testing.T) {
	st := testStore(t)
	ok, err := st.UpsertCapability(context.Background(), Capability{
		Hostname: "cap-host-does-not-exist", Kind: "openstack", Role: "compute", Detected: true,
	})
	if err != nil {
		t.Fatalf("UpsertCapability: %v", err)
	}
	if ok {
		t.Error("a capability was recorded for a host that is not in the inventory")
	}
}

// A probe that fails must not erase what it last found. Deleting the rows would
// turn a timeout into "this host runs nothing", which reads as a decommission.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityErrorKeepsTheLastKnownFacts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-02"
	seedCapabilityHost(t, st, host)

	if _, err := st.UpsertCapability(ctx, Capability{
		Hostname: host, Kind: "openstack", Role: "compute", Detected: true,
		Components: map[string]CapabilityComponent{"nova-compute": {Version: "31.2.0", Active: true}},
	}); err != nil {
		t.Fatalf("seed capability: %v", err)
	}
	if err := st.RecordCapabilityError(ctx, host, "openstack", "ssh timeout"); err != nil {
		t.Fatalf("RecordCapabilityError: %v", err)
	}

	rows, _ := st.Capabilities(ctx, "openstack")
	for _, r := range rows {
		if r.Hostname != host {
			continue
		}
		if r.LastError != "ssh timeout" {
			t.Errorf("last_error = %q, want the probe's message", r.LastError)
		}
		if !r.Detected || r.Components["nova-compute"].Version != "31.2.0" {
			t.Errorf("the failed probe erased the facts: detected=%v components=%+v", r.Detected, r.Components)
		}
		return
	}
	t.Fatalf("%s disappeared from the listing after a probe error", host)
}

// "Probed and found nothing" is a row; "never probed" is no row. A listing that
// cannot tell them apart reads an unprobed fleet as an empty one.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityRecordsAnAbsentPlatform(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-03"
	seedCapabilityHost(t, st, host)

	if _, err := st.UpsertCapability(ctx, Capability{
		Hostname: host, Kind: "openstack", Role: "none", Detected: false,
	}); err != nil {
		t.Fatalf("UpsertCapability: %v", err)
	}
	rows, _ := st.Capabilities(ctx, "openstack")
	for _, r := range rows {
		if r.Hostname == host {
			if r.Detected {
				t.Error("an absent platform was recorded as detected")
			}
			return
		}
	}
	t.Error("an absent platform left no row, so it cannot be told from never having been probed")
}
