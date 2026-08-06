package wireguard

import (
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// The accuracy fixture: production's *shape*, none of its identifiers.
//
// The individual tests in this package each pin one defect. This pins the
// combination, because the defects were not independent — the duplicate key and
// the interface-name mismatch met on the same pair of hosts, and fixing edge
// identity without fixing endpoint identity would have reproduced last-write-wins
// one layer down. A fixture that holds all of them at once is what catches that.
//
// Measured against the production database on 2026-08-03:
//
//	interfaces  19 across 12 hosts     peers 30
//	both ends   22                     external 10
//	iface names 16 mismatched           6 matched
//	duplicate public keys  2 (both the same machine under two inventory names)
//
// Both mismatch and match are present in the real fleet and they fail
// differently — mismatch used to split one tunnel into two edges, match used to
// let the second poll erase the first. A fixture with only one of them would
// have looked complete and covered half the bug.
//
// Names and addresses are synthetic: hostnames carry no customer or site names,
// and addresses come from the documentation ranges (RFC 5737 / RFC 1918). Real
// hostnames in this fleet embed tenant names, which is why the shape is copied
// and the identifiers are not.
const (
	fixtureCollectedAt = "2026-07-28T09:06:56Z" // ~6 days before the reading, as production was
)

func wgAccuracyFixture() (ifaces []store.WGInterfaceRow, peers []store.WGPeerRow, at time.Time) {
	at, _ = time.Parse(time.RFC3339, fixtureCollectedAt)
	ifc := func(host, name, key string, port int, addr string) store.WGInterfaceRow {
		return store.WGInterfaceRow{
			WGInterface: store.WGInterface{
				Host: host, Iface: name, PublicKey: key, ListenPort: port, Address: []string{addr},
			},
			CollectedAt: at,
		}
	}
	p := func(host, name, peerKey, endpoint string, allowed ...string) store.WGPeerRow {
		return store.WGPeerRow{WGPeer: store.WGPeer{
			Host: host, Iface: name, PeerPubKey: peerKey, Endpoint: endpoint, AllowedIPs: allowed,
		}}
	}

	ifaces = []store.WGInterfaceRow{
		// Hub: several interfaces, so the layout elects it.
		ifc("hub-gw", "wg3", "KHUB3", 51823, "10.0.3.1"),
		ifc("hub-gw", "wg1", "KHUB1", 51821, "10.0.1.1"),
		// Compute nodes name their side wg0 while the hub names it wg3 — the
		// mismatch that used to split one tunnel into two edges.
		ifc("node-a", "wg0", "KNODEA", 51820, "10.0.3.2"),
		ifc("node-b", "wg0", "KNODEB", 51820, "10.0.3.3"),
		// Matching interface names on both ends — the case where the two polls
		// used to land on one id and overwrite each other.
		ifc("peer-gw", "wg1", "KPEER1", 51821, "10.0.1.2"),
		// One machine under two inventory names: a VIP and its host. Identical
		// down to the port and address, which is what makes it a merge and not a
		// conflict.
		ifc("lb-vip", "wg9", "KSHARED", 51829, "10.0.9.1"),
		ifc("lb-host", "wg9", "KSHARED", 51829, "10.0.9.1"),
	}

	peers = []store.WGPeerRow{
		// Mismatched-name tunnels, both directions collected.
		p("hub-gw", "wg3", "KNODEA", "192.0.2.11:51820", "10.0.3.2/32"),
		p("node-a", "wg0", "KHUB3", "192.0.2.1:51823", "10.0.3.0/24"),
		p("hub-gw", "wg3", "KNODEB", "192.0.2.12:51820", "10.0.3.3/32"),
		p("node-b", "wg0", "KHUB3", "192.0.2.1:51823", "10.0.3.0/24"),
		// Matching-name tunnel, both directions collected.
		p("hub-gw", "wg1", "KPEER1", "198.51.100.2:51821", "10.0.1.2/32"),
		p("peer-gw", "wg1", "KHUB1", "192.0.2.1:51821", "10.0.1.0/24"),
		// External peers: no interface row behind the key, so one-sided.
		p("hub-gw", "wg3", "KROAMING1", "203.0.113.7:51820", "10.0.3.50/32"),
		p("hub-gw", "wg3", "KROAMING2", "203.0.113.8:51820", "10.0.3.51/32"),
	}
	return ifaces, peers, at
}

// One tunnel is one edge whichever names its ends use, and every edge keeps both
// ends' interfaces and per-direction routes.
func TestAccuracyFixtureOneEdgePerTunnel(t *testing.T) {
	ifaces, peers, _ := wgAccuracyFixture()
	topo, edgeFor := Build(ifaces, peers, nil, nil)

	// 3 both-ends tunnels + 2 external = 5.
	if got := len(topo.Edges); got != 5 {
		ids := make([]string, 0, len(topo.Edges))
		for _, e := range topo.Edges {
			ids = append(ids, e.ID)
		}
		t.Fatalf("edges = %d, want 5 (3 tunnels + 2 external): %v", got, ids)
	}

	// Every both-ends tunnel: both sides attribute to the same edge.
	for _, pair := range [][2]TunnelKey{
		{{"hub-gw", "wg3", "KNODEA"}, {"node-a", "wg0", "KHUB3"}},
		{{"hub-gw", "wg3", "KNODEB"}, {"node-b", "wg0", "KHUB3"}},
		{{"hub-gw", "wg1", "KPEER1"}, {"peer-gw", "wg1", "KHUB1"}},
	} {
		a, b := edgeFor[pair[0]], edgeFor[pair[1]]
		if a == "" || a != b {
			t.Errorf("%v and %v map to %q and %q; the ends of one tunnel must share an edge", pair[0], pair[1], a, b)
		}
	}

	// The mismatched tunnel keeps wg3 on one end and wg0 on the other.
	var mismatched *Edge
	for i := range topo.Edges {
		e := &topo.Edges[i]
		if e.A != nil && e.B != nil && e.A.Iface != e.B.Iface {
			mismatched = e
			break
		}
	}
	if mismatched == nil {
		t.Fatal("no edge carries two different interface names; the mismatch case is not covered")
	}
	if mismatched.A.Allowed == mismatched.B.Allowed {
		t.Errorf("both ends carry the same routes (%q); AllowedIPs are per-direction", mismatched.A.Allowed)
	}
}

// The duplicate key is one machine under two names. Merging is right; warning is
// not — the production pair matches down to the listen port and address, and
// flagging it would report a normal VIP arrangement as a fault.
func TestAccuracyFixtureMergesTheVIPWithoutWarning(t *testing.T) {
	ifaces, _, _ := wgAccuracyFixture()
	idx := BuildEndpointIndex(ifaces)

	if idx.conflicts["KSHARED"] {
		t.Error("the VIP and its host were reported as an identity conflict")
	}
	seen := idx.ObservedThrough("KSHARED")
	if len(seen) != 2 {
		t.Fatalf("observedThrough = %v, want both inventory names", seen)
	}
	// Deterministic, so the graph does not change between runs of the same data.
	again := BuildEndpointIndex(ifaces)
	if a, b := idx.canonical["KSHARED"], again.canonical["KSHARED"]; a != b {
		t.Errorf("canonical owner is not stable: %v vs %v", a, b)
	}
}

// The snapshot's age has to reach the response. Six days of structure under a
// two-second animation is what made the page read as current.
func TestAccuracyFixtureCarriesItsAge(t *testing.T) {
	ifaces, peers, at := wgAccuracyFixture()
	topo, _ := Build(ifaces, peers, nil, nil)
	if !topo.CollectedAt.Equal(at) {
		t.Errorf("CollectedAt = %v, want %v", topo.CollectedAt, at)
	}
	if age := time.Since(topo.CollectedAt); age < 24*time.Hour {
		t.Errorf("the fixture is only %v old; it exists to exercise a stale snapshot", age)
	}
}

// Both gateways poll the same tunnel and report from opposite directions. The
// matching-interface tunnel is where a whole-struct assignment used to let the
// later poll erase the earlier one.
func TestAccuracyFixtureKeepsBothEndsOfEveryTunnel(t *testing.T) {
	ifaces, peers, _ := wgAccuracyFixture()
	_, edgeFor := Build(ifaces, peers, nil, nil)
	st := NewState()
	now := time.Now()

	poll := func(at time.Time, rxHub, txHub int64) {
		st.Record("hub-gw", []PeerSample{
			{Iface: "wg1", PubKey: "KPEER1", Rx: rxHub, Tx: txHub, Handshake: at.Unix()},
		}, at, edgeFor)
		st.Record("peer-gw", []PeerSample{
			{Iface: "wg1", PubKey: "KHUB1", Rx: txHub, Tx: rxHub, Handshake: at.Unix()},
		}, at, edgeFor)
	}
	poll(now, 0, 0)
	poll(now.Add(10*time.Second), 1_000, 50_000)

	id := edgeFor[TunnelKey{"hub-gw", "wg1", "KPEER1"}]
	st.mu.Lock()
	got := st.stats[id]
	st.mu.Unlock()

	if len(got.Sides) != 2 {
		t.Fatalf("tunnel holds %d sides, want both gateways: %+v", len(got.Sides), got.Sides)
	}
	hub, peer := got.Sides["hub-gw"], got.Sides["peer-gw"]
	if hub.TxPS != peer.RxPS || hub.RxPS != peer.TxPS {
		t.Errorf("the ends disagree about the same bytes: hub=%+v peer=%+v", hub, peer)
	}
}

// A tunnel nothing polled must stay in the denominator. Counting only the
// samples that arrived is what made "12 of 30 observed, 12 fine" render as
// all-clear.
func TestAccuracyFixtureCountsUnpolledTunnels(t *testing.T) {
	ifaces, peers, _ := wgAccuracyFixture()
	topo, edgeFor := Build(ifaces, peers, nil, nil)
	st := NewState()
	now := time.Now()

	// Poll exactly one gateway; everything else goes unobserved.
	st.Record("hub-gw", []PeerSample{
		{Iface: "wg3", PubKey: "KNODEA", Handshake: now.Unix()},
	}, now, edgeFor)

	st.mu.Lock()
	polled := len(st.stats)
	st.mu.Unlock()
	if polled >= len(topo.Edges) {
		t.Fatalf("the fixture cannot exercise partial coverage: %d polled of %d edges", polled, len(topo.Edges))
	}
	// The page counts over topo.edges, so the gap has to be visible there.
	if len(topo.Edges)-polled < 1 {
		t.Error("no unobserved tunnel remains to count")
	}
}

// Anonymisation is part of the fixture's contract: this repository is public,
// and real hostnames in this fleet embed tenant names.
func TestAccuracyFixtureCarriesNoRealIdentifiers(t *testing.T) {
	ifaces, peers, _ := wgAccuracyFixture()
	var text []string
	for _, i := range ifaces {
		text = append(text, i.Host, i.Iface, i.PublicKey, strings.Join(i.Address, ","))
	}
	for _, p := range peers {
		text = append(text, p.Host, p.Iface, p.PeerPubKey, p.Endpoint, strings.Join(p.AllowedIPs, ","))
	}
	joined := strings.ToLower(strings.Join(text, " "))

	// Real inventory prefixes and site names from this fleet.
	for _, leaked := range []string{"sre-srv", "sre-lb", "incheon", "seoul", "coex", "gpu0", "[admin]", "surromind"} {
		if strings.Contains(joined, leaked) {
			t.Errorf("the fixture carries a real identifier: %q", leaked)
		}
	}
	// Addresses must come from the documentation/private ranges.
	for _, p := range peers {
		if p.Endpoint == "" {
			continue
		}
		ok := false
		for _, prefix := range []string{"192.0.2.", "198.51.100.", "203.0.113."} {
			if strings.HasPrefix(p.Endpoint, prefix) {
				ok = true
			}
		}
		if !ok {
			t.Errorf("endpoint %q is outside the documentation ranges", p.Endpoint)
		}
	}
}
