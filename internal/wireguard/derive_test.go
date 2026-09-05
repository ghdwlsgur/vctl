package wireguard

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// deriveFixture declares one farm around the collected gateway of
// declaredFixture, plus a tunnel nobody synced on a declared VM, so every
// derivation has one real and one declared-only instance to get right.
func deriveFixture() Topology {
	ifaces, peers, servers, ann := declaredFixture()
	ents := []store.NetEntity{
		{ID: "site/a", Kind: "site"},
		{ID: "farm/x", Kind: "farm", Site: "site-a"},
		{ID: "host/h1", Kind: "physical-host", Site: "site-a"},
		{ID: "vm/v2", Kind: "vm", Site: "site-a"},
		{ID: "tunnel/gw1/wg0", Kind: "tunnel", Attrs: map[string]any{"host": "gw1", "iface": "wg0"}},
		{ID: "tunnel/t2/wg0", Kind: "tunnel", Attrs: map[string]any{"host": "v2", "iface": "wg0", "collected": false}},
		{ID: "net/x/tenant", Kind: "network", Attrs: map[string]any{"cidr": "192.0.2.0/24"}},
		{ID: "net/x/other", Kind: "network", Attrs: map[string]any{"cidr": "198.51.100.0/24"}},
		{ID: "net/x/lonely", Kind: "network", Attrs: map[string]any{"cidr": "203.0.113.0/24"}},
		{ID: "egress/e1", Kind: "egress"},
		{ID: "edge/fw", Kind: "edge"},
	}
	rels := []store.NetRelation{
		{SrcID: "farm/x", DstID: "site/a", Kind: "member-of"},
		{SrcID: "host/h1", DstID: "farm/x", Kind: "member-of"},
		{SrcID: "vm/v2", DstID: "host/h1", Kind: "placed-on"},
		{SrcID: "tunnel/gw1/wg0", DstID: "net/x/tenant", Kind: "carries",
			Attrs: map[string]any{"method": "direct", "snat_at": "gw1", "oif": []any{"eth0", "eth1"}, "nft_table": "wg-nat"}},
		{SrcID: "tunnel/gw1/wg0", DstID: "edge/fw", Kind: "transits", Attrs: map[string]any{"order": float64(2)}},
		{SrcID: "tunnel/gw1/wg0", DstID: "egress/e1", Kind: "transits", Attrs: map[string]any{"order": float64(1)}},
		{SrcID: "tunnel/t2/wg0", DstID: "net/x/other", Kind: "carries", Attrs: map[string]any{"method": "proxy"}},
	}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, rels)
	return topo
}

func findPath(d Derived, network string) *Path {
	for i := range d.Paths {
		if d.Paths[i].Network == network {
			return &d.Paths[i]
		}
	}
	return nil
}

// The physical host under the gateway is the domain that matters: it must list
// the collected gateway, the declared VM, and the unsynced tunnel on that VM —
// three different ways of being placed on one machine.
func TestDeriveFailureDomainCollectsEveryPlacement(t *testing.T) {
	d := Derive(deriveFixture())
	if len(d.FailureDomains) == 0 {
		t.Fatalf("no failure domains derived")
	}
	fd := d.FailureDomains[0]
	if fd.Host != PhysicalHostNodeID("h1") {
		t.Fatalf("widest domain should be host|h1, got %+v", fd)
	}
	wantDeps := []string{"gw1", "tunnel/t2/wg0", "vm/v2"}
	if !reflect.DeepEqual(fd.Dependents, wantDeps) {
		t.Errorf("dependents = %v, want %v", fd.Dependents, wantDeps)
	}
	wantTunnels := []string{"gw1", "tunnel/t2/wg0"}
	if !reflect.DeepEqual(fd.Tunnels, wantTunnels) {
		t.Errorf("tunnels = %v, want %v", fd.Tunnels, wantTunnels)
	}
	if fd.Farm != "farm/x" || fd.Site == "" {
		t.Errorf("domain should resolve farm and site: %+v", fd)
	}
	if fd.Carries != 2 {
		t.Errorf("carries = %d, want 2 (one per tunnel on the host)", fd.Carries)
	}
}

// A path climbs tunnel → host → farm → site, then follows transits in declared
// order, and ends at the network. The transit order comes from attrs, not from
// the order relations happened to be stored in.
func TestDerivePathHopsFollowPlacementThenTransits(t *testing.T) {
	d := Derive(deriveFixture())
	p := findPath(d, "net/x/tenant")
	if p == nil {
		t.Fatalf("no path for net/x/tenant: %+v", d.Paths)
	}
	want := []string{"gw1", PhysicalHostNodeID("h1"), "farm/x", "site/a", "egress/e1", "edge/fw", "net/x/tenant"}
	if !reflect.DeepEqual(p.Hops, want) {
		t.Errorf("hops = %v, want %v", p.Hops, want)
	}
	if p.Method != "direct" || p.SNATAt != "gw1" || p.CIDR != "192.0.2.0/24" || p.Uncollected {
		t.Errorf("path fields = %+v", p)
	}
}

// A declared tunnel nobody synced still gets a path — through the VM it names —
// and is marked so the page can draw it as unconfirmed.
func TestDeriveUncollectedTunnelPathGoesThroughItsVM(t *testing.T) {
	d := Derive(deriveFixture())
	p := findPath(d, "net/x/other")
	if p == nil {
		t.Fatalf("no path for net/x/other: %+v", d.Paths)
	}
	want := []string{"tunnel/t2/wg0", "vm/v2", PhysicalHostNodeID("h1"), "farm/x", "site/a", "net/x/other"}
	if !reflect.DeepEqual(p.Hops, want) {
		t.Errorf("hops = %v, want %v", p.Hops, want)
	}
	if !p.Uncollected || p.Method != "proxy" {
		t.Errorf("path should be flagged uncollected with method proxy: %+v", p)
	}
}

// Only direct carries with a declared SNAT host require a masquerade; proxy and
// dnat terminate elsewhere. The rule carries the pinned interfaces and table so
// a NAT contract can be generated from it.
func TestDeriveSNATRulesOnlyFromDirectCarries(t *testing.T) {
	d := Derive(deriveFixture())
	if len(d.SNAT) != 1 {
		t.Fatalf("snat rules = %+v, want exactly one", d.SNAT)
	}
	want := SNATRule{At: "gw1", Tunnel: "gw1", Iface: "wg0", Network: "net/x/tenant", CIDR: "192.0.2.0/24", OIF: []string{"eth0", "eth1"}, Table: "wg-nat"}
	if !reflect.DeepEqual(d.SNAT[0], want) {
		t.Errorf("snat = %+v, want %+v", d.SNAT[0], want)
	}
}

func TestDeriveGapsNameWhatNothingConfirms(t *testing.T) {
	d := Derive(deriveFixture())
	got := map[string]string{}
	for _, g := range d.Gaps {
		got[g.Subject] = g.Kind
	}
	if got["tunnel/t2/wg0"] != "uncollected-tunnel" {
		t.Errorf("unsynced declared tunnel not reported: %+v", d.Gaps)
	}
	if got["net/x/lonely"] != "uncarried-network" {
		t.Errorf("network nobody carries not reported: %+v", d.Gaps)
	}
	if _, ok := got["net/x/tenant"]; ok {
		t.Errorf("a carried network must not be a gap")
	}
	if _, ok := got["vm/v2"]; ok {
		t.Errorf("a placed VM must not be a gap")
	}
}

// When the sync placed a gateway on one host and the declaration on another,
// neither is silently preferred: the conflict is a gap.
func TestDeriveReportsPlacementConflict(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture() // gw1 synced on h1
	ents := []store.NetEntity{
		{ID: "host/h1", Kind: "physical-host"},
		{ID: "host/h2", Kind: "physical-host"},
		{ID: "vm/gw1-vm", Kind: "vm", Attrs: map[string]any{"inventory": "gw1"}},
	}
	rels := []store.NetRelation{{SrcID: "vm/gw1-vm", DstID: "host/h2", Kind: "placed-on"}}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, rels)
	d := Derive(topo)
	var found *Gap
	for i := range d.Gaps {
		if d.Gaps[i].Kind == "placement-conflict" && d.Gaps[i].Subject == "gw1" {
			found = &d.Gaps[i]
		}
	}
	if found == nil {
		t.Fatalf("no placement-conflict for gw1; gaps=%+v", d.Gaps)
	}
	if !strings.Contains(found.Detail, PhysicalHostNodeID("h1")) || !strings.Contains(found.Detail, PhysicalHostNodeID("h2")) {
		t.Errorf("conflict should name both hosts: %q", found.Detail)
	}
}

// A graph with nothing declared derives to empty, not nil, slices — the page
// reads a stable shape either way.
func TestDeriveOnPlainGraphIsEmptyNotNil(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture()
	topo, _ := Build(ifaces, peers, servers, ann)
	d := Derive(topo)
	if d.Paths == nil || d.SNAT == nil || d.FailureDomains == nil {
		t.Errorf("derived slices must be non-nil: %+v", d)
	}
	if len(d.Paths) != 0 || len(d.SNAT) != 0 {
		t.Errorf("nothing declared should derive no paths or rules: %+v", d)
	}
}
