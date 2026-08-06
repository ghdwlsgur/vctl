package wireguard

import (
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// aliasFixture: one machine under two inventory names (a VIP and its host),
// running two interfaces, with a real far end on the personal tunnel.
//
// This is the production shape that the earlier fixes did not reach. The
// endpoint index already knew the two names were one machine, but the graph was
// still built per hostname, so the knowledge never arrived where it mattered.
func aliasFixture() ([]store.WGInterfaceRow, []store.WGPeerRow) {
	i := func(host, name, key string, port int, addr string) store.WGInterfaceRow {
		return store.WGInterfaceRow{WGInterface: store.WGInterface{
			Host: host, Iface: name, PublicKey: key, ListenPort: port, Address: []string{addr},
		}}
	}
	p := func(host, name, peerKey string, allowed ...string) store.WGPeerRow {
		return store.WGPeerRow{WGPeer: store.WGPeer{
			Host: host, Iface: name, PeerPubKey: peerKey, AllowedIPs: allowed,
		}}
	}
	ifaces := []store.WGInterfaceRow{
		i("lb-vip", "wg-personal", "KPERSONAL", 51910, "10.0.94.1"),
		i("lb-host", "wg-personal", "KPERSONAL", 51910, "10.0.94.1"),
		i("lb-vip", "wg1", "KWG1", 51821, "10.0.91.1"),
		i("lb-host", "wg1", "KWG1", 51821, "10.0.91.1"),
		i("far-gw", "wg-remote", "KFAR", 51910, "10.0.94.2"),
	}
	peers := []store.WGPeerRow{
		p("lb-vip", "wg-personal", "KFAR", "10.0.94.2/32"),
		p("lb-host", "wg-personal", "KFAR", "10.0.94.2/32"),
		p("far-gw", "wg-remote", "KPERSONAL", "10.0.94.0/24"),
	}
	return ifaces, peers
}

// Two inventory names for one box must produce one node. The endpoint index knew
// this already; addGateways built nodes per hostname and undid it, so the graph
// drew the same machine twice with identical interfaces and keys.
func TestAliasHostsCollapseToOneGatewayNode(t *testing.T) {
	ifaces, peers := aliasFixture()
	topo, _ := Build(ifaces, peers, nil, nil)

	gws := 0
	var lb *Node
	for i := range topo.Nodes {
		if topo.Nodes[i].Kind != "gateway" {
			continue
		}
		gws++
		if len(topo.Nodes[i].Ifaces) == 2 {
			lb = &topo.Nodes[i]
		}
	}
	if gws != 2 {
		t.Fatalf("gateway nodes = %d, want 2 (the shared box and the far end)", gws)
	}
	if lb == nil {
		t.Fatal("no node carries both interfaces of the shared box")
	}
	if len(lb.SeenAs) != 2 {
		t.Errorf("SeenAs = %v, want both inventory names kept", lb.SeenAs)
	}
}

// The alias row must not take the far side of the tunnel. Matching on host+iface
// called it "a different side", so it filled B and the real far end — arriving
// later — found B occupied and was dropped.
func TestAliasRowDoesNotTakeTheFarSide(t *testing.T) {
	ifaces, peers := aliasFixture()
	topo, _ := Build(ifaces, peers, nil, nil)

	var tunnel *Edge
	for i := range topo.Edges {
		if topo.Edges[i].A != nil && topo.Edges[i].B != nil {
			tunnel = &topo.Edges[i]
			break
		}
	}
	if tunnel == nil {
		t.Fatal("no two-sided tunnel was built")
	}
	if tunnel.A.PubKey == tunnel.B.PubKey {
		t.Fatalf("both ends carry the same key %q; the alias took the far side", tunnel.A.PubKey)
	}
	keys := map[string]bool{tunnel.A.PubKey: true, tunnel.B.PubKey: true}
	if !keys["KPERSONAL"] || !keys["KFAR"] {
		t.Errorf("ends are %q and %q, want the shared box and the real far end", tunnel.A.PubKey, tunnel.B.PubKey)
	}
}

// Every two-sided edge is between two distinct endpoints, by construction. This
// is the invariant the alias bug broke, stated once for all edges rather than
// for the one tunnel above.
func TestEveryTwoSidedEdgeJoinsTwoDistinctEndpoints(t *testing.T) {
	ifaces, peers := aliasFixture()
	topo, _ := Build(ifaces, peers, nil, nil)
	for _, e := range topo.Edges {
		if e.A == nil || e.B == nil {
			continue
		}
		if e.A.PubKey == e.B.PubKey {
			t.Errorf("edge %s joins one endpoint to itself (%s)", e.ID, e.A.PubKey)
		}
	}
}

// Edges name nodes, and only canonical hosts have nodes. An edge pointing at an
// alias dangles.
func TestEdgeEndpointsNameNodesThatExist(t *testing.T) {
	ifaces, peers := aliasFixture()
	topo, _ := Build(ifaces, peers, nil, nil)
	have := map[string]bool{}
	for _, n := range topo.Nodes {
		have[n.ID] = true
	}
	for _, e := range topo.Edges {
		for _, id := range []string{e.Source, e.Target} {
			if !have[id] {
				t.Errorf("edge %s points at %q, which is not a node", e.ID, id)
			}
		}
	}
}

// A gateway carries a key per interface. Keeping only the first meant a VIP that
// named any other interface could never match exactly and fell through to the
// label guess.
func TestGatewayNodeCarriesEveryInterfaceKey(t *testing.T) {
	ifaces, peers := aliasFixture()
	topo, _ := Build(ifaces, peers, nil, nil)

	for _, n := range topo.Nodes {
		if len(n.Ifaces) < 2 {
			continue
		}
		keys := map[string]bool{}
		for _, i := range n.Ifaces {
			if i.PubKey == "" {
				t.Errorf("%s/%s carries no key", n.ID, i.Name)
			}
			keys[i.PubKey] = true
		}
		if !keys["KPERSONAL"] || !keys["KWG1"] {
			t.Errorf("node %s keys = %v, want both interfaces' keys", n.ID, keys)
		}
		return
	}
	t.Fatal("no multi-interface gateway in the fixture")
}

// Two machines that merely share one interface key are still two machines.
// Merging on any shared key would collapse unrelated hosts.
func TestHostsSharingOneInterfaceStaySeparate(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "host-a", Iface: "wg0", PublicKey: "SHARED", ListenPort: 51820, Address: []string{"10.0.0.1"}}},
		{WGInterface: store.WGInterface{Host: "host-b", Iface: "wg0", PublicKey: "SHARED", ListenPort: 51820, Address: []string{"10.0.0.1"}}},
		// host-b also runs an interface host-a does not have, so they are not the
		// same box however much wg0 matches.
		{WGInterface: store.WGInterface{Host: "host-b", Iface: "wg7", PublicKey: "ONLYB", ListenPort: 51827, Address: []string{"10.0.7.1"}}},
	}
	topo, _ := Build(ifaces, nil, nil, nil)
	gws := 0
	for _, n := range topo.Nodes {
		if n.Kind == "gateway" {
			gws++
		}
	}
	if gws != 2 {
		t.Errorf("gateway nodes = %d, want 2; a partially shared key is not one machine", gws)
	}
}
