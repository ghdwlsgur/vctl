package openstack

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// The key is the pair TenantJump matches on. Name alone would paint two
// projects' unrelated "private" networks as one wire — a jump the domain
// layer refuses looking possible on screen.
func TestVMNetKeyIsProjectScoped(t *testing.T) {
	a := store.InstanceAddress{NetworkName: "private", Address: "10.0.0.5"}
	k1 := vmNetKey(store.Instance{ProjectID: "p1"}, a)
	k2 := vmNetKey(store.Instance{ProjectID: "p2"}, a)
	if k1 == k2 {
		t.Errorf("the same network name in two projects shares a key: %q", k1)
	}
}

// Rows collected before network_name existed still have to group somehow, and
// the band an operator means by "the .201 network" is the grouping they get.
func TestVMNetKeyFallsBackToTheAddressBand(t *testing.T) {
	v := store.Instance{ProjectID: "p1"}
	same := vmNetKey(v, store.InstanceAddress{Address: "10.0.5.12"}) ==
		vmNetKey(v, store.InstanceAddress{Address: "10.0.5.200"})
	if !same {
		t.Error("two addresses in one /24 got different keys")
	}
	diff := vmNetKey(v, store.InstanceAddress{Address: "10.0.5.12"}) !=
		vmNetKey(v, store.InstanceAddress{Address: "10.0.6.12"})
	if !diff {
		t.Error("two /24s share a key")
	}
	// An unparseable address is its own band, never a panic: it can only have
	// come from the database, and a listing must draw over whatever is there.
	if got := vmNetKey(v, store.InstanceAddress{Address: "not-an-ip"}); !strings.Contains(got, "not-an-ip") {
		t.Errorf("junk address key = %q", got)
	}
}

// The mapping is a property of the farm's set of networks, not of row order:
// a network must keep its color across refreshes, filters, and between the
// list and the detail behind enter.
func TestNetPaletteIsStableAcrossRowOrder(t *testing.T) {
	a := store.Instance{ProjectID: "p1", Addresses: []store.InstanceAddress{
		{NetworkName: "blue", Address: "10.0.0.5"}}}
	b := store.Instance{ProjectID: "p1", Addresses: []store.InstanceAddress{
		{NetworkName: "green", Address: "10.0.1.5"}}}
	fwd := newNetPalette([]store.Instance{a, b})
	rev := newNetPalette([]store.Instance{b, a})
	for k, st := range fwd {
		if rev[k].GetForeground() != st.GetForeground() {
			t.Errorf("key %q changed color with row order", k)
		}
	}
	ka, kb := vmNetKey(a, a.Addresses[0]), vmNetKey(b, b.Addresses[0])
	if fwd[ka].GetForeground() == fwd[kb].GetForeground() {
		t.Error("two networks in one small farm share a color")
	}
}

// The dots are what make the jump legible: the shown address painted by its
// network, then one dot per further network — not per further address.
func TestAddressPartsDedupsNetworks(t *testing.T) {
	v := store.Instance{ProjectID: "p1", Addresses: []store.InstanceAddress{
		// Nova files a floating address under its port's network, so these two
		// are one wire and must yield no dot.
		{NetworkName: "blue", Address: "192.168.201.45", Type: "floating"},
		{NetworkName: "blue", Address: "10.0.5.12", Type: "fixed"},
		{NetworkName: "storage", Address: "10.9.0.12", Type: "fixed"},
	}}
	best, others := addressParts(v, []string{"192.168."})
	if best == nil || best.Address != "192.168.201.45" {
		t.Fatalf("best = %+v, want the floating address", best)
	}
	if len(others) != 1 || !strings.Contains(others[0], "storage") {
		t.Errorf("others = %v, want just the storage network", others)
	}
	// And the cell shows them: the address leading, one dot following.
	got := addressCell(v, []string{"192.168."}, nil)
	if !strings.HasPrefix(got, "192.168.201.45") || strings.Count(got, "●") != 1 {
		t.Errorf("addressCell = %q, want the floating address and one dot", got)
	}
}

// A VM with no addresses renders as an empty cell, not a panic — a building
// VM or one whose port was detached is a normal row.
func TestAddressCellSurvivesNoAddresses(t *testing.T) {
	if got := addressCell(store.Instance{}, nil, nil); got != "" {
		t.Errorf("addressCell = %q, want empty", got)
	}
}
