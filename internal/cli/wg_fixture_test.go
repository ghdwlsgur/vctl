package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// wgDashboardFixture builds the topology used to exercise the `vctl wg serve`
// dashboard in a browser. It runs through the real buildWGTopology so the shape
// matches what the served /topology endpoint produces, and it is deliberately
// wide enough to reach every branch the wiring renderer can take.
//
// Branch preconditions, read off render() in wg_serve.html:
//   - mesh stack    — one interface with >=4 peers whose allowed lists hold no
//     CIDR wider than /32 (wg5 below).
//   - two zones     — zoneKey is dc.split("-")[0], so the hub's dc prefix must
//     differ from the far endpoints' (incheon vs seoul).
//   - top spokes    — peers whose zone equals the hub's (lb-gw).
//   - far spokes    — peers in another zone; these are what land in epPos.
//   - hop chain     — an edge between two non-hub nodes where one end is a far
//     spoke and the other sits in the hub's zone (seoul-gw <-> relay-01).
//   - external hop  — same, but the far end is an uncollected peer.
//   - VIP owner     — a DNAT VIP whose label names its endpoint.
//   - warning badge — two annotations on one host disagreeing on the label.
//
// TestWGDashboardFixtureCoversRenderBranches locks those preconditions down, so
// an edit that quietly flattens the fixture fails instead of silently shrinking
// what the browser harness can check.
func wgDashboardFixture() wgTopology {
	ifaces := []store.WGInterfaceRow{
		// Hub owns the most interfaces, so prep() elects it hub.
		{WGInterface: store.WGInterface{Host: "wg-hub", Iface: "wg0", ListenPort: 51820, PublicKey: "HUB0"}},
		{WGInterface: store.WGInterface{Host: "wg-hub", Iface: "wg1", ListenPort: 51821, PublicKey: "HUB1"}},
		{WGInterface: store.WGInterface{Host: "wg-hub", Iface: "wg3", ListenPort: 51823, PublicKey: "HUB3"}},
		{WGInterface: store.WGInterface{Host: "wg-hub", Iface: "wg5", ListenPort: 51825, PublicKey: "HUB5"}},
		// Same-zone spoke that fronts a DNAT VIP.
		{WGInterface: store.WGInterface{Host: "lb-gw", Iface: "wg3", ListenPort: 51823, PublicKey: "LB3"}},
		// Other-zone gateway: becomes a far spoke, so it can anchor hop legs.
		{WGInterface: store.WGInterface{Host: "seoul-gw", Iface: "wg1", ListenPort: 51821, PublicKey: "SEOUL1"}},
		{WGInterface: store.WGInterface{Host: "seoul-gw", Iface: "wg7", ListenPort: 51827, PublicKey: "SEOUL7"}},
		{WGInterface: store.WGInterface{Host: "seoul-gw", Iface: "wg8", ListenPort: 51828, PublicKey: "SEOUL8"}},
		// Hub-zone transit target for the hop chain.
		{WGInterface: store.WGInterface{Host: "relay-01", Iface: "wg7", ListenPort: 51827, PublicKey: "RELAY7"}},
	}

	peers := []store.WGPeerRow{
		// wg0 fan-out: three independent branches off one hub interface.
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg0", PeerPubKey: "PEERA",
			Endpoint: "198.51.100.11:51820", AllowedIPs: []string{"10.10.1.0/24"}}},
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg0", PeerPubKey: "PEERB",
			Endpoint: "198.51.100.12:51820", AllowedIPs: []string{"10.10.2.0/24"}}},
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg0", PeerPubKey: "PEERC",
			Endpoint: "198.51.100.13:51820", AllowedIPs: []string{"10.10.3.0/24"}}},
		// wg1 point-to-point to the other-zone gateway.
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg1", PeerPubKey: "SEOUL1",
			Endpoint: "198.51.100.21:51821", AllowedIPs: []string{"10.20.0.0/24"}}},
		{WGPeer: store.WGPeer{Host: "seoul-gw", Iface: "wg1", PeerPubKey: "HUB1",
			Endpoint: "198.51.100.1:51821", AllowedIPs: []string{"10.20.1.0/24"}}},
		// wg3 to the VIP owner.
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg3", PeerPubKey: "LB3",
			Endpoint: "198.51.100.41:51823", AllowedIPs: []string{"10.40.0.0/24", "10.99.0.7/32"}}},
		{WGPeer: store.WGPeer{Host: "lb-gw", Iface: "wg3", PeerPubKey: "HUB3",
			Endpoint: "198.51.100.1:51823", AllowedIPs: []string{"10.40.1.0/24"}}},
		// wg5 mesh: >=4 peers, /32 only, so meshIf picks it up.
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg5", PeerPubKey: "MESH1",
			Endpoint: "198.51.100.51:51825", AllowedIPs: []string{"10.88.0.2/32"}}},
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg5", PeerPubKey: "MESH2",
			Endpoint: "198.51.100.52:51825", AllowedIPs: []string{"10.88.0.3/32"}}},
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg5", PeerPubKey: "MESH3",
			Endpoint: "198.51.100.53:51825", AllowedIPs: []string{"10.88.0.4/32"}}},
		{WGPeer: store.WGPeer{Host: "wg-hub", Iface: "wg5", PeerPubKey: "MESH4",
			Endpoint: "198.51.100.54:51825", AllowedIPs: []string{"10.88.0.5/32"}}},
		// Hop chain: far spoke (seoul-gw) <-> hub-zone transit node (relay-01).
		{WGPeer: store.WGPeer{Host: "seoul-gw", Iface: "wg7", PeerPubKey: "RELAY7",
			Endpoint: "198.51.100.61:51827", AllowedIPs: []string{"10.70.0.0/24"}}},
		// External hop: far spoke <-> uncollected peer.
		{WGPeer: store.WGPeer{Host: "seoul-gw", Iface: "wg8", PeerPubKey: "OUTSIDER",
			Endpoint: "203.0.113.9:51828", AllowedIPs: []string{"10.80.0.0/24"}}},
	}

	servers := []store.Server{
		{Hostname: "wg-hub", IP: "192.0.2.1", DC: "incheon-vm"},
		{Hostname: "lb-gw", IP: "192.0.2.41", DC: "incheon-vm"},
		{Hostname: "relay-01", IP: "192.0.2.61", DC: "incheon-vm"},
		{Hostname: "seoul-gw", IP: "192.0.2.21", DC: "seoul-onprem"},
		{Hostname: "plain-host-01", IP: "192.0.2.60", DC: "incheon-vm"},
	}

	annotations := []store.WGEndpointAnnotation{
		{PublicKey: "PEERA", Label: "branch-a", Kind: "vm", UnderlayIP: "10.10.1.5", Site: "seoul-onprem"},
		{PublicKey: "PEERB", Label: "branch-b", Kind: "device", UnderlayIP: "10.10.2.5", Site: "seoul-onprem"},
		// Two annotations on one collected host disagree on the label, which is
		// what raises the endpoint card's WARNING badge.
		{PublicKey: "SEOUL1", Label: "seoul-gw", Kind: "gateway", Site: "seoul-onprem"},
		{PublicKey: "SEOUL7", Label: "seoul-gw-alt", Kind: "gateway", Site: "seoul-onprem"},
	}

	topo, _ := buildWGTopology(ifaces, peers, servers, annotations)
	// A VIP attaches to the endpoint whose label's first token appears in the VIP
	// label, so the label has to name lb-gw for the wg3 focus path to see it.
	topo.Vips = append(topo.Vips, wgVip{IP: "10.99.0.7", Label: "lb-gw tunnel DNAT (wg3)", Iface: "wg3", Note: "dnat"})
	return topo
}

// TestWGDashboardFixtureDump writes the fixture where a browser harness can load
// it as window.WG_BOOT, which is how the dashboard gets driven without a database
// or SSH. Skipped unless asked for, so normal runs and CI stay unaffected.
//
//	WG_FIXTURE_OUT=/tmp/topology.json go test ./internal/cli/ -run TestWGDashboardFixtureDump
//
// Then splice a <script>window.WG_BOOT={topology:<that json>,frames:[]}</script>
// ahead of wg_serve.html's own <script> and open the result.
func TestWGDashboardFixtureDump(t *testing.T) {
	out := os.Getenv("WG_FIXTURE_OUT")
	if out == "" {
		t.Skip("WG_FIXTURE_OUT not set")
	}
	topo := wgDashboardFixture()
	b, err := json.MarshalIndent(topo, "", " ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(out, b, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("nodes=%d edges=%d aggs=%d links=%d vips=%d",
		len(topo.Nodes), len(topo.Edges), len(topo.Aggs), len(topo.Links), len(topo.Vips))
}

// TestWGDashboardFixtureCoversRenderBranches asserts the fixture still satisfies
// each renderer branch's precondition. Without this the fixture can decay into
// one that only draws the simple hub-and-spoke case, and the browser checks it
// feeds would keep passing while covering far less.
func TestWGDashboardFixtureCoversRenderBranches(t *testing.T) {
	topo := wgDashboardFixture()

	hub := ""
	most := 0
	byIface := map[string][]wgEdge{}
	zones := map[string]bool{}
	kinds := map[string]bool{}
	for _, n := range topo.Nodes {
		if n.Kind == "gateway" && len(n.Ifaces) > most {
			most, hub = len(n.Ifaces), n.ID
		}
		kinds[n.Kind] = true
		if n.DC != "" {
			zones[strings.Split(n.DC, "-")[0]] = true
		}
	}
	if hub == "" {
		t.Fatal("no hub gateway in fixture")
	}
	for _, e := range topo.Edges {
		byIface[e.Iface] = append(byIface[e.Iface], e)
	}

	// mesh stack: >=4 peers on one interface, none routing wider than a /32.
	mesh := false
	for _, edges := range byIface {
		if len(edges) < 4 {
			continue
		}
		wide := false
		for _, e := range edges {
			for _, c := range strings.Split(e.Allowed, ",") {
				if c = strings.TrimSpace(c); c != "" && !strings.HasSuffix(c, "/32") {
					wide = true
				}
			}
		}
		if !wide {
			mesh = true
		}
	}
	if !mesh {
		t.Error("no mesh interface: need >=4 peers on one iface with /32-only allowed IPs")
	}

	if len(zones) < 2 {
		t.Errorf("fixture has %d zone(s); the two-column zone layout needs >=2 dc prefixes", len(zones))
	}
	if !kinds["external"] {
		t.Error("no external peer: the external column and ext-hop branch stay unrendered")
	}
	if !kinds["vm"] {
		t.Error("no vm endpoint: the vm card variant stays unrendered")
	}

	// hop chain: an edge touching neither end of the hub.
	hops := 0
	for _, e := range topo.Edges {
		if e.Source != hub && e.Target != hub {
			hops++
		}
	}
	if hops < 2 {
		t.Errorf("fixture has %d hop edge(s); need one inter-zone hop plus one external hop", hops)
	}

	// VIP owner: a VIP whose label names a node, or attachVips finds nothing.
	vipMatched := false
	for _, v := range topo.Vips {
		for _, n := range topo.Nodes {
			tok := strings.FieldsFunc(n.Label, func(r rune) bool { return r == ' ' || r == '(' })
			if len(tok) > 0 && tok[0] != "" && strings.Contains(v.Label, tok[0]) && v.Iface != "" {
				vipMatched = true
			}
		}
	}
	if !vipMatched {
		t.Error("no VIP whose label names an endpoint: the DNAT focus path stays unexercised")
	}

	// warning badge: some node carries a conflicting-annotation warning.
	warned := false
	for _, n := range topo.Nodes {
		if len(n.Warnings) > 0 {
			warned = true
		}
	}
	if !warned {
		t.Error("no node warnings: the endpoint card's WARNING badge stays unrendered")
	}
}
