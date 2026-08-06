package wireguard

import (
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// A gateway node has to carry its public key, because that is what a VIP points
// at. Matching on a substring of the display label is what this replaces.
func TestGatewayNodeCarriesItsPublicKey(t *testing.T) {
	topo, _ := Build(
		[]store.WGInterfaceRow{iface("gw-a", "wg0", "AKEY", 51820, "10.0.1.1")},
		nil, nil, nil)

	n := topologyNode(topo, "gw-a")
	if n == nil {
		t.Fatal("gateway node missing")
	}
	if n.PubKey != "AKEY" {
		t.Errorf("node.PubKey = %q, want the interface's key", n.PubKey)
	}
}

// One machine under two inventory names should say so on the node, not silently
// render as whichever name sorted first.
func TestGatewayNodeNamesEveryHostItWasSeenAs(t *testing.T) {
	topo, _ := Build([]store.WGInterfaceRow{
		iface("sre-srv-0049", "wg1", "LBKEY", 51821, "10.0.91.1"),
		iface("sre-lb", "wg1", "LBKEY", 51821, "10.0.91.1"),
	}, nil, nil, nil)

	var withSeen *Node
	for i := range topo.Nodes {
		if len(topo.Nodes[i].SeenAs) > 0 {
			withSeen = &topo.Nodes[i]
			break
		}
	}
	if withSeen == nil {
		t.Fatalf("no node reports the two names: %+v", topo.Nodes)
	}
	if len(withSeen.SeenAs) != 2 {
		t.Errorf("SeenAs = %v, want both hostnames", withSeen.SeenAs)
	}
}
