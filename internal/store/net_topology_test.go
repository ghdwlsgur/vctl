package store

import (
	"context"
	"testing"
)

// Integration — needs VCTL_TEST_DSN. Round-trips an entity and a relation
// through JSONB, then checks that deleting an entity takes its relations with
// it, which is the one behaviour the schema promises beyond plain storage.
func TestNetTopologyRoundTripAndCascade(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Example ranges only: this repository is public.
	farm := NetEntity{ID: "farm/x", Kind: "farm", Label: "farm x", Site: "site-a"}
	net := NetEntity{
		ID: "net/x/tenant-net", Kind: "network", Label: "tenant net", Site: "site-a",
		Attrs: map[string]any{"cidr": "192.0.2.0/24"},
	}
	tun := NetEntity{
		ID: "tunnel/gw/wg0", Kind: "tunnel", Site: "site-a",
		Attrs: map[string]any{"host": "gw", "iface": "wg0"},
	}
	for _, e := range []NetEntity{farm, net, tun} {
		t.Cleanup(func() { _ = st.NetEntityDelete(ctx, e.ID) })
		if err := st.NetEntityUpsert(ctx, e); err != nil {
			t.Fatalf("upsert %s: %v", e.ID, err)
		}
	}

	carries := NetRelation{
		SrcID: tun.ID, DstID: net.ID, Kind: "carries",
		Attrs: map[string]any{"method": "direct", "oif": []any{"ens3", "ens4"}},
	}
	if err := st.NetRelationUpsert(ctx, carries); err != nil {
		t.Fatalf("relation upsert: %v", err)
	}

	ents, err := st.NetEntities(ctx)
	if err != nil {
		t.Fatalf("list entities: %v", err)
	}
	var gotNet *NetEntity
	for i := range ents {
		if ents[i].ID == net.ID {
			gotNet = &ents[i]
		}
	}
	if gotNet == nil {
		t.Fatalf("network entity missing from listing")
	}
	if gotNet.Attrs["cidr"] != "192.0.2.0/24" {
		t.Fatalf("attrs did not round-trip: %#v", gotNet.Attrs)
	}

	rels, err := st.NetRelations(ctx)
	if err != nil {
		t.Fatalf("list relations: %v", err)
	}
	var gotRel *NetRelation
	for i := range rels {
		if rels[i].SrcID == tun.ID && rels[i].DstID == net.ID && rels[i].Kind == "carries" {
			gotRel = &rels[i]
		}
	}
	if gotRel == nil {
		t.Fatalf("carries relation missing from listing")
	}
	if gotRel.Attrs["method"] != "direct" {
		t.Fatalf("relation attrs did not round-trip: %#v", gotRel.Attrs)
	}
	oif, ok := gotRel.Attrs["oif"].([]any)
	if !ok || len(oif) != 2 {
		t.Fatalf("array attr did not round-trip: %#v", gotRel.Attrs["oif"])
	}

	// Deleting the tunnel must cascade to the relation that hangs off it.
	if err := st.NetEntityDelete(ctx, tun.ID); err != nil {
		t.Fatalf("delete tunnel: %v", err)
	}
	rels, err = st.NetRelations(ctx)
	if err != nil {
		t.Fatalf("list relations after delete: %v", err)
	}
	for _, r := range rels {
		if r.SrcID == tun.ID {
			t.Fatalf("relation survived entity delete: %+v", r)
		}
	}
}

// A relation to an undeclared entity is a mistake, not a fact; the foreign key
// has to reject it rather than let a dangling edge into the graph.
func TestNetRelationRejectsUndeclaredEndpoint(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	err := st.NetRelationUpsert(ctx, NetRelation{
		SrcID: "tunnel/nobody/wg9", DstID: "net/nowhere/none", Kind: "carries",
	})
	if err == nil {
		t.Fatalf("expected foreign-key rejection for undeclared endpoints")
	}
}
