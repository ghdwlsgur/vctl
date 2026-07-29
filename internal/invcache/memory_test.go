package invcache

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// fixture mirrors the shape ListWithStatus returns: operator inventory joined
// with whatever the node-agent last observed.
func fixture() *Snapshot {
	seen := time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)
	return &Snapshot{
		Version:    snapshotVersion,
		CapturedAt: seen,
		Servers: []store.ServerWithStatus{
			{Server: store.Server{Hostname: "sre-srv-0047", IP: "192.0.2.47", Port: 22, User: "ubuntu", DC: "incheon", ExtraIPs: []string{"10.1.0.47"}}},
			{
				Server: store.Server{Hostname: "sre-srv-0048", IP: "192.0.2.48", Port: 22, User: "ubuntu", DC: "incheon", JumpVia: "sre-bastion"},
				Status: &store.ServerStatus{Hostname: "sre-srv-0048", LastSeenAt: seen, ObservedIPs: []string{"172.16.0.48"}},
			},
			{Server: store.Server{Hostname: "sre-bastion", IP: "192.0.2.10", Port: 22, User: "ubuntu", DC: "seoul-onprem", ExtraIPs: []string{"2001:db8::1"}}},
		},
	}
}

func TestGetExactAndMissing(t *testing.T) {
	m := NewMemory(fixture())
	sv, err := m.Get(context.Background(), "sre-bastion")
	if err != nil || sv.IP != "192.0.2.10" {
		t.Fatalf("Get(sre-bastion) = %+v, %v", sv, err)
	}
	if _, err := m.Get(context.Background(), "nope"); err == nil {
		t.Fatal("Get of an unknown host returned no error")
	}
}

// Resolve's IP branch has to search all three address sets, not just the
// primary column — `vctl ssh <ip>` matching online but not offline would be a
// silent regression exactly when someone is troubleshooting.
func TestResolveMatchesEveryAddressSet(t *testing.T) {
	m := NewMemory(fixture())
	for _, tc := range []struct {
		query, want string
	}{
		{"192.0.2.47", "sre-srv-0047"},  // primary ip
		{"10.1.0.47", "sre-srv-0047"},   // operator-set extra_ips
		{"172.16.0.48", "sre-srv-0048"}, // agent-observed
		// Addresses are compared as parsed IPs, not text, matching Postgres
		// inet equality: an expanded IPv6 form finds the host stored in
		// compressed form.
		{"2001:0db8:0000:0000:0000:0000:0000:0001", "sre-bastion"},
	} {
		sv, cands, err := m.Resolve(context.Background(), tc.query)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tc.query, err)
		}
		if sv == nil {
			t.Fatalf("Resolve(%q) did not resolve to one host (candidates %d)", tc.query, len(cands))
		}
		if sv.Hostname != tc.want {
			t.Errorf("Resolve(%q) = %q, want %q", tc.query, sv.Hostname, tc.want)
		}
	}
}

func TestResolveFuzzyAndAmbiguous(t *testing.T) {
	m := NewMemory(fixture())

	sv, _, err := m.Resolve(context.Background(), "0047")
	if err != nil || sv == nil || sv.Hostname != "sre-srv-0047" {
		t.Fatalf("fuzzy Resolve(0047) = %+v, %v", sv, err)
	}

	// "srv" hits two hosts: the caller must get both, sorted, to pick from.
	sv, cands, err := m.Resolve(context.Background(), "srv")
	if err != nil {
		t.Fatal(err)
	}
	if sv != nil {
		t.Fatalf("ambiguous Resolve returned a single host %q", sv.Hostname)
	}
	if len(cands) != 2 || cands[0].Hostname != "sre-srv-0047" || cands[1].Hostname != "sre-srv-0048" {
		t.Fatalf("ambiguous candidates = %+v", cands)
	}
}

// Postgres interpolates the query into an ILIKE pattern, so `_` is a wildcard
// server-side. The offline path has to agree or the same command finds
// different hosts depending on whether the database happens to be up.
func TestResolveHonoursLikeWildcardsAndCase(t *testing.T) {
	m := NewMemory(fixture())
	for _, q := range []string{"SRE-SRV-0047", "sre_srv_0047", "sre%0047"} {
		sv, cands, err := m.Resolve(context.Background(), q)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", q, err)
		}
		if sv == nil || sv.Hostname != "sre-srv-0047" {
			t.Errorf("Resolve(%q) = %v (candidates %d), want sre-srv-0047", q, sv, len(cands))
		}
	}
}

func TestListFiltersAndOrders(t *testing.T) {
	m := NewMemory(fixture())
	got, err := m.List(context.Background(), "incheon")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Hostname != "sre-srv-0047" {
		t.Fatalf("List(incheon) = %+v", got)
	}
	all, _ := m.List(context.Background(), "")
	if len(all) != 3 {
		t.Fatalf("List(all) returned %d hosts", len(all))
	}
}

// ListInventory is derived from the status rows rather than fetched separately,
// so the address merge and agent heartbeat have to survive the derivation.
func TestListInventoryDerivesAddressesAndAgent(t *testing.T) {
	m := NewMemory(fixture())
	rows, err := m.ListInventory(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	byHost := map[string]store.InventoryRow{}
	for _, r := range rows {
		byHost[r.Hostname] = r
	}

	got := byHost["sre-srv-0047"]
	if len(got.Addresses) != 2 || got.Addresses[0] != "192.0.2.47" || got.Addresses[1] != "10.1.0.47" {
		t.Errorf("addresses = %v, want primary first then extras", got.Addresses)
	}
	if got.AgentSeen != nil {
		t.Errorf("host with no status reported an agent heartbeat")
	}
	if seen := byHost["sre-srv-0048"].AgentSeen; seen == nil {
		t.Error("host with status lost its agent heartbeat")
	}
}

// A caller that sorts or appends to a result must not reach into the snapshot;
// the Postgres path hands out fresh values every query and the cache has to
// match, or the two diverge under identical code.
func TestReadsDoNotAliasTheSnapshot(t *testing.T) {
	snap := fixture()
	m := NewMemory(snap)

	sv, err := m.Get(context.Background(), "sre-srv-0047")
	if err != nil {
		t.Fatal(err)
	}
	sv.ExtraIPs[0] = "mutated"
	sv.Hostname = "mutated"

	if snap.Servers[0].ExtraIPs[0] != "10.1.0.47" || snap.Servers[0].Hostname != "sre-srv-0047" {
		t.Fatalf("mutating a result changed the snapshot: %+v", snap.Servers[0])
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	f := &FileStore{Path: filepath.Join(t.TempDir(), "cache", "inventory.json")}

	if _, err := f.Load(); err == nil {
		t.Fatal("loading a missing snapshot returned no error")
	}

	snap := fixture()
	snap.SetGrants("test-user", []string{"ssh", "sync"}, snap.CapturedAt)
	if err := f.Save(snap); err != nil {
		t.Fatal(err)
	}

	got, err := f.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Servers) != 3 {
		t.Fatalf("round-tripped %d hosts, want 3", len(got.Servers))
	}
	g, ok := got.Grant("test-user")
	if !ok || !g.Has("ssh") || g.Has("trust-ca") {
		t.Fatalf("round-tripped grants = %+v (ok=%v)", g, ok)
	}
	// Status must survive: dropping it would make every cached host look
	// agent-less, which reads as a fleet-wide outage.
	var withStatus int
	for _, s := range got.Servers {
		if s.Status != nil {
			withStatus++
		}
	}
	if withStatus != 1 {
		t.Fatalf("%d hosts kept status, want 1", withStatus)
	}

	if err := f.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Load(); err == nil {
		t.Fatal("snapshot survived Clear")
	}
}

// A snapshot from an older binary is discarded rather than half-read.
func TestFileStoreRejectsForeignVersion(t *testing.T) {
	f := &FileStore{Path: filepath.Join(t.TempDir(), "inventory.json")}
	snap := fixture()
	if err := f.Save(snap); err != nil {
		t.Fatal(err)
	}
	stale := fixture()
	stale.Version = snapshotVersion + 1
	// Save() stamps the current version, so write the foreign one directly.
	if err := writeRaw(t, f.Path, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Load(); err == nil {
		t.Fatal("a foreign snapshot version was accepted")
	}
}
