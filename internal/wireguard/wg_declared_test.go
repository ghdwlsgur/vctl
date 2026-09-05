package wireguard

import (
	"reflect"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// declaredFixture is one collected gateway VM placed on a physical host by
// annotation, so the graph already has a `host|h1` node for a declaration to
// reconcile onto. Example ranges only: this repository is public.
func declaredFixture() ([]store.WGInterfaceRow, []store.WGPeerRow, []store.Server, []store.WGEndpointAnnotation) {
	ifaces := []store.WGInterfaceRow{{WGInterface: store.WGInterface{
		Host: "gw1", Iface: "wg0", PublicKey: "KGW1", ListenPort: 51820, Address: []string{"10.0.90.2"},
	}}}
	peers := []store.WGPeerRow{{WGPeer: store.WGPeer{
		Host: "gw1", Iface: "wg0", PeerPubKey: "KFAR", Endpoint: "198.51.100.7:51820", AllowedIPs: []string{"192.0.2.0/24"},
	}}}
	servers := []store.Server{
		{Hostname: "gw1", IP: "203.0.113.10", DC: "site-a"},
		{Hostname: "h1", IP: "203.0.113.1", DC: "site-a"},
	}
	annotations := []store.WGEndpointAnnotation{{
		PublicKey: "KGW1", Kind: "vm", InventoryHost: "gw1", ParentHostname: "h1",
	}}
	return ifaces, peers, servers, annotations
}

func findLink(topo Topology, src, kind, dst string) *Link {
	for i := range topo.Links {
		l := &topo.Links[i]
		if l.Source == src && l.Kind == kind && l.Target == dst {
			return l
		}
	}
	return nil
}

// The additive promise: with nothing declared, the new build path is the old
// build path. No layer, no attrs, nothing re-sorted differently.
func TestBuildWithoutDeclaredIsUnchanged(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture()
	before, edgesBefore := Build(ifaces, peers, servers, ann)
	after, edgesAfter := BuildWithDeclared(ifaces, peers, servers, ann, nil, nil)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("BuildWithDeclared(nil, nil) differs from Build:\n%+v\n%+v", before, after)
	}
	if !reflect.DeepEqual(edgesBefore, edgesAfter) {
		t.Fatalf("edge map differs with nothing declared")
	}
	for _, n := range after.Nodes {
		if n.Layer != "" || n.Attrs != nil {
			t.Fatalf("node %s carries declared-only fields with nothing declared: %+v", n.ID, n)
		}
	}
}

// A declared physical host that inventory already placed must enrich the
// existing `host|` node, not stand next to it as a second box.
func TestDeclaredPhysicalHostReconcilesOntoDerivedNode(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture()
	ents := []store.NetEntity{
		{ID: "host/h1", Kind: "physical-host", Label: "h1", Site: "site-a", Attrs: map[string]any{"rack": "R1"}},
		{ID: "farm/x", Kind: "farm", Label: "farm x", Site: "site-a"},
	}
	rels := []store.NetRelation{{SrcID: "host/h1", DstID: "farm/x", Kind: "member-of"}}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, rels)

	host := topologyNode(topo, PhysicalHostNodeID("h1"))
	if host == nil {
		t.Fatalf("fixture did not produce a derived physical-host node; nodes=%v", nodeIDs(topo))
	}
	if topologyNode(topo, "host/h1") != nil {
		t.Fatalf("declared host became a duplicate node instead of reconciling")
	}
	if host.Layer != "underlay" {
		t.Errorf("reconciled host layer = %q, want underlay", host.Layer)
	}
	if host.Attrs["rack"] != "R1" {
		t.Errorf("declared attrs did not reach the reconciled node: %#v", host.Attrs)
	}
	if findLink(topo, PhysicalHostNodeID("h1"), "member-of", "farm/x") == nil {
		t.Errorf("member-of link should resolve its source to the reconciled node id; links=%+v", topo.Links)
	}
}

// A declared tunnel that names a collected gateway interface is that gateway.
// Its relations must attach to the gateway node, and no phantom tunnel node may
// appear.
func TestDeclaredTunnelAliasesToCollectedGateway(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture()
	ents := []store.NetEntity{
		{ID: "tunnel/gw1/wg0", Kind: "tunnel", Attrs: map[string]any{"host": "gw1", "iface": "wg0"}},
		{ID: "net/x/tenant", Kind: "network", Label: "tenant", Site: "site-b", Attrs: map[string]any{"cidr": "192.0.2.0/24"}},
	}
	rels := []store.NetRelation{{
		SrcID: "tunnel/gw1/wg0", DstID: "net/x/tenant", Kind: "carries",
		Attrs: map[string]any{"method": "direct", "snat_at": "gw1"},
	}}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, rels)

	if topologyNode(topo, "tunnel/gw1/wg0") != nil {
		t.Fatalf("declared tunnel became its own node instead of aliasing the gateway")
	}
	l := findLink(topo, "gw1", "carries", "net/x/tenant")
	if l == nil {
		t.Fatalf("carries link should hang off the gateway node; links=%+v", topo.Links)
	}
	if l.Attrs["method"] != "direct" || l.Attrs["snat_at"] != "gw1" {
		t.Errorf("relation attrs did not pass through: %#v", l.Attrs)
	}
	gw := topologyNode(topo, "gw1")
	if gw == nil || gw.Layer != "overlay" {
		t.Errorf("collected gateway should be overlay once declarations exist; got %+v", gw)
	}
}

// Entities the collected graph knows nothing about become underlay nodes with
// their kind and attrs intact — that is the whole point of declaring them.
func TestDeclaredOnlyEntitiesBecomeUnderlayNodes(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture()
	ents := []store.NetEntity{
		{ID: "site/a", Kind: "site", Label: "site a"},
		{ID: "edge/fw1", Kind: "edge", Label: "fw 1", Site: "site-a", Attrs: map[string]any{"public_ip": "198.51.100.1"}},
		{ID: "egress/198.51.100.1", Kind: "egress", Site: "site-a"},
	}
	rels := []store.NetRelation{
		{SrcID: "edge/fw1", DstID: "site/a", Kind: "member-of"},
		{SrcID: "edge/fw1", DstID: "egress/198.51.100.1", Kind: "transits", Attrs: map[string]any{"order": float64(1)}},
	}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, rels)

	for _, id := range []string{"site/a", "edge/fw1", "egress/198.51.100.1"} {
		n := topologyNode(topo, id)
		if n == nil {
			t.Fatalf("declared entity %s missing; nodes=%v", id, nodeIDs(topo))
		}
		if n.Layer != "underlay" {
			t.Errorf("%s layer = %q, want underlay", id, n.Layer)
		}
	}
	if topologyNode(topo, "edge/fw1").Attrs["public_ip"] != "198.51.100.1" {
		t.Errorf("entity attrs lost")
	}
	if topologyNode(topo, "egress/198.51.100.1").Label != "egress/198.51.100.1" {
		t.Errorf("an unlabelled entity should fall back to its id as label")
	}
	if findLink(topo, "edge/fw1", "transits", "egress/198.51.100.1") == nil {
		t.Errorf("transits link missing; links=%+v", topo.Links)
	}
}

// A declared physical host nobody has collected is still a physical host, and
// the page keys those by `host|`; the declaration's own `host/` id is an input
// spelling, not a second node shape.
func TestDeclaredOnlyPhysicalHostTakesCollectedIDShape(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture()
	ents := []store.NetEntity{
		{ID: "host/h2", Kind: "physical-host", Site: "site-a", Attrs: map[string]any{"role": "compute"}},
		{ID: "farm/x", Kind: "farm", Label: "farm x", Site: "site-a"},
	}
	rels := []store.NetRelation{{SrcID: "host/h2", DstID: "farm/x", Kind: "member-of"}}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, rels)

	if topologyNode(topo, "host/h2") != nil {
		t.Fatalf("declared-only host kept its declaration id instead of host|h2")
	}
	n := topologyNode(topo, PhysicalHostNodeID("h2"))
	if n == nil {
		t.Fatalf("host|h2 missing; nodes=%v", nodeIDs(topo))
	}
	if n.Label != "h2" || n.Layer != "underlay" || n.Attrs["role"] != "compute" {
		t.Errorf("declared-only host node = %+v", n)
	}
	if findLink(topo, PhysicalHostNodeID("h2"), "member-of", "farm/x") == nil {
		t.Errorf("member-of link should follow the host to its host| id; links=%+v", topo.Links)
	}
}

// A peer annotated as a physical host is drawn under its public key. Declaring
// that host must land on that node, not open a second box beside it.
func TestDeclaredPhysicalHostReconcilesOntoAnnotatedEndpoint(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture()
	ann = append(ann, store.WGEndpointAnnotation{
		PublicKey: "KFAR", Kind: "physical-host", InventoryHost: "h3", Label: "h3",
	})
	ents := []store.NetEntity{
		{ID: "host/h3", Kind: "physical-host", Site: "site-b", Attrs: map[string]any{"ip": "198.51.100.7"}},
	}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, nil)

	ep := topologyNode(topo, "endpoint|KFAR")
	if ep == nil || ep.Kind != "physical-host" {
		t.Fatalf("fixture did not yield an annotated physical-host endpoint; nodes=%v", nodeIDs(topo))
	}
	if topologyNode(topo, PhysicalHostNodeID("h3")) != nil {
		t.Fatalf("declared host duplicated the annotated endpoint")
	}
	if ep.Attrs["ip"] != "198.51.100.7" || ep.Layer != "underlay" {
		t.Errorf("declaration did not enrich the endpoint node: %+v", ep)
	}
}

// The hub is one machine: the sync draws it as a gateway, the operator declares
// it as a VM with placement. Declaring must land on the collected node.
func TestDeclaredVMAliasesToCollectedGateway(t *testing.T) {
	ifaces, peers, servers, ann := declaredFixture()
	ents := []store.NetEntity{
		{ID: "vm/gw1-vm", Kind: "vm", Label: "gateway VM", Site: "site-a", Attrs: map[string]any{"inventory": "gw1", "fip": "203.0.113.10"}},
		{ID: "host/h1", Kind: "physical-host", Site: "site-a"},
	}
	rels := []store.NetRelation{{SrcID: "vm/gw1-vm", DstID: "host/h1", Kind: "placed-on"}}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, rels)

	if topologyNode(topo, "vm/gw1-vm") != nil {
		t.Fatalf("declared VM became a second node beside the collected gateway")
	}
	gw := topologyNode(topo, "gw1")
	if gw == nil || gw.Attrs["fip"] != "203.0.113.10" {
		t.Fatalf("declaration did not enrich the gateway node: %+v", gw)
	}
	if findLink(topo, "gw1", "placed-on", PhysicalHostNodeID("h1")) == nil {
		t.Errorf("placed-on should hang off the gateway node; links=%+v", topo.Links)
	}
}

// A physical machine that runs WireGuard itself is the gateway the sync drew.
// Declaring it as a physical host must land on that node — the load balancer
// that is also a tunnel endpoint is one box, not a host beside a gateway.
func TestDeclaredPhysicalHostAliasesToGatewayThatIsTheMachine(t *testing.T) {
	ifaces, peers, servers, _ := declaredFixture()
	var ann []store.WGEndpointAnnotation // gw1 is then a bare gateway: no VM annotation, no parent
	ents := []store.NetEntity{
		{ID: "host/gw1", Kind: "physical-host", Site: "site-a", Attrs: map[string]any{"role": "lb"}},
		{ID: "site/a", Kind: "site"},
		{ID: "tunnel/gw1/wg0", Kind: "tunnel", Attrs: map[string]any{"host": "gw1", "iface": "wg0"}},
		{ID: "net/a/x", Kind: "network"},
	}
	rels := []store.NetRelation{
		{SrcID: "host/gw1", DstID: "site/a", Kind: "member-of"},
		{SrcID: "tunnel/gw1/wg0", DstID: "net/a/x", Kind: "carries", Attrs: map[string]any{"method": "direct"}},
	}
	topo, _ := BuildWithDeclared(ifaces, peers, servers, ann, ents, rels)
	if topologyNode(topo, PhysicalHostNodeID("gw1")) != nil {
		t.Fatalf("declared host duplicated the gateway node; nodes=%v", nodeIDs(topo))
	}
	gw := topologyNode(topo, "gw1")
	if gw == nil || gw.Attrs["role"] != "lb" || gw.Layer != "underlay" {
		t.Fatalf("gateway node should carry the declaration and sit in the underlay: %+v", gw)
	}
	if findLink(topo, "gw1", "member-of", "site/a") == nil {
		t.Errorf("member-of should hang off the gateway node; links=%+v", topo.Links)
	}
	l := findLink(topo, "gw1", "carries", "net/a/x")
	if l == nil || l.Attrs["iface"] != "wg0" {
		t.Errorf("carries link should name the interface of the aliased tunnel: %+v", l)
	}
}

func nodeIDs(topo Topology) []string {
	ids := make([]string, 0, len(topo.Nodes))
	for _, n := range topo.Nodes {
		ids = append(ids, n.ID)
	}
	return ids
}
