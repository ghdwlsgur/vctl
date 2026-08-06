package wireguard

import (
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func iface(host, name, key string, port int, addrs ...string) store.WGInterfaceRow {
	return store.WGInterfaceRow{
		WGInterface: store.WGInterface{
			Host: host, Iface: name, PublicKey: key, ListenPort: port, Address: addrs,
		},
	}
}

func peer(host, name, peerKey string, allowed ...string) store.WGPeerRow {
	return store.WGPeerRow{
		WGPeer: store.WGPeer{Host: host, Iface: name, PeerPubKey: peerKey, AllowedIPs: allowed},
	}
}

// One machine reachable under two inventory names is polled twice, and both rows
// describe the same interface. That is not two endpoints, and it is not a fault:
// in this fleet sre-lb is a VIP living on sre-srv-0049, matching down to the
// listen port and address.
//
// Warning about it would report a normal arrangement as a conflict, which is
// worse than saying nothing. What the reader needs is that the endpoint answers
// to two names.
func TestEndpointIndexMergesOneMachineSeenUnderTwoNames(t *testing.T) {
	idx := BuildEndpointIndex([]store.WGInterfaceRow{
		iface("sre-srv-0049", "wg1", "KEY1", 51821, "10.0.91.1"),
		iface("sre-lb", "wg1", "KEY1", 51821, "10.0.91.1"),
	})

	if idx.conflicts["KEY1"] {
		t.Error("identical observations were reported as an identity conflict")
	}
	got := idx.ObservedThrough("KEY1")
	if len(got) != 2 || got[0] != "sre-lb" || got[1] != "sre-srv-0049" {
		t.Errorf("observedThrough = %v, want both names sorted", got)
	}
}

// The same key on interfaces that genuinely differ means two machines are
// presenting one identity. That is the case worth flagging.
func TestEndpointIndexFlagsGenuinelyDifferentInterfaces(t *testing.T) {
	for name, rows := range map[string][]store.WGInterfaceRow{
		"다른 포트": {
			iface("gw-a", "wg0", "KEY1", 51820, "10.0.1.1"),
			iface("gw-b", "wg0", "KEY1", 51999, "10.0.1.1"),
		},
		"다른 주소": {
			iface("gw-a", "wg0", "KEY1", 51820, "10.0.1.1"),
			iface("gw-b", "wg0", "KEY1", 51820, "10.0.9.9"),
		},
		"다른 iface 이름": {
			iface("gw-a", "wg0", "KEY1", 51820, "10.0.1.1"),
			iface("gw-b", "wg7", "KEY1", 51820, "10.0.1.1"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if !BuildEndpointIndex(rows).conflicts["KEY1"] {
				t.Error("disagreeing observations were not flagged as a conflict")
			}
		})
	}
}

// Last-write-wins made the graph depend on scan order: the same rows in a
// different order picked a different owner, and nothing on screen said so.
func TestEndpointIndexPicksTheSameOwnerRegardlessOfRowOrder(t *testing.T) {
	a := BuildEndpointIndex([]store.WGInterfaceRow{
		iface("sre-srv-0049", "wg1", "KEY1", 51821, "10.0.91.1"),
		iface("sre-lb", "wg1", "KEY1", 51821, "10.0.91.1"),
	})
	b := BuildEndpointIndex([]store.WGInterfaceRow{
		iface("sre-lb", "wg1", "KEY1", 51821, "10.0.91.1"),
		iface("sre-srv-0049", "wg1", "KEY1", 51821, "10.0.91.1"),
	})
	ra, _ := a.Lookup("KEY1")
	rb, _ := b.Lookup("KEY1")
	if ra != rb {
		t.Errorf("owner depends on row order: %v vs %v", ra, rb)
	}
	if ra.Host != "sre-lb" {
		t.Errorf("canonical owner = %q, want the lexically smallest name", ra.Host)
	}
}

// Interface names are per host and often differ across one tunnel. This fleet
// has 7 such tunnels — wg3 on the hub, wg0 on each GPU node — and the old id
// carried the observing side's name, so one tunnel became two edges each
// showing one direction.
func TestOneTunnelIsOneEdgeWhenInterfaceNamesDiffer(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		iface("wg-hub", "wg3", "HUBKEY", 51823, "10.0.3.1"),
		iface("gpu-01", "wg0", "GPUKEY", 51820, "10.0.3.2"),
	}
	peers := []store.WGPeerRow{
		peer("wg-hub", "wg3", "GPUKEY", "10.0.3.2/32"),
		peer("gpu-01", "wg0", "HUBKEY", "10.0.3.0/24"),
	}
	topo, edgeFor := Build(ifaces, peers, nil, nil)

	if n := len(topo.Edges); n != 1 {
		t.Fatalf("one tunnel produced %d edges: %+v", n, topo.Edges)
	}
	// Both ends must attribute their samples to that one edge, or their traffic
	// lands on different rows.
	hub := edgeFor[TunnelKey{"wg-hub", "wg3", "GPUKEY"}]
	gpu := edgeFor[TunnelKey{"gpu-01", "wg0", "HUBKEY"}]
	if hub == "" || hub != gpu {
		t.Errorf("ends map to different edges: %q vs %q", hub, gpu)
	}

	// And both interface names survive. The tunnel is wg3 at one end and wg0 at
	// the other; a single "iface" field can only be one of them.
	e := topo.Edges[0]
	if e.A == nil || e.B == nil {
		t.Fatalf("edge does not carry both ends: %+v", e)
	}
	names := map[string]string{e.A.Host: e.A.Iface, e.B.Host: e.B.Iface}
	if names["wg-hub"] != "wg3" || names["gpu-01"] != "wg0" {
		t.Errorf("interface names lost: %v", names)
	}
	// AllowedIPs are per-direction routes, so both sides' must survive too.
	routes := map[string]string{e.A.Host: e.A.Allowed, e.B.Host: e.B.Allowed}
	if routes["wg-hub"] != "10.0.3.2/32" || routes["gpu-01"] != "10.0.3.0/24" {
		t.Errorf("per-direction routes lost: %v", routes)
	}
}

// The edge id must not depend on which side is read first.
func TestTunnelEdgeIDIsTheSameFromEitherEnd(t *testing.T) {
	if a, b := TunnelEdgeID("AAA", "BBB"), TunnelEdgeID("BBB", "AAA"); a != b {
		t.Errorf("edge id depends on the observing side: %q vs %q", a, b)
	}
}

// Both gateways poll the same tunnel and report from their own perspective:
// A's tx is B's rx. Assigning the whole stat let whichever polled later erase
// the other, so the drawn direction flipped with poll timing rather than with
// traffic.
func TestBothEndsOfATunnelKeepTheirOwnMeasurement(t *testing.T) {
	st := NewState()
	edgeFor := map[TunnelKey]string{
		{"wg-hub", "wg3", "GPUKEY"}: "gw|A|B",
		{"gpu-01", "wg0", "HUBKEY"}: "gw|A|B",
	}
	now := time.Now()

	// Two polls per side so a rate can be computed at all.
	st.Record("wg-hub", []PeerSample{{Iface: "wg3", PubKey: "GPUKEY", Rx: 0, Tx: 0, Handshake: now.Unix()}}, now, edgeFor)
	st.Record("gpu-01", []PeerSample{{Iface: "wg0", PubKey: "HUBKEY", Rx: 0, Tx: 0, Handshake: now.Unix()}}, now, edgeFor)
	later := now.Add(10 * time.Second)
	st.Record("wg-hub", []PeerSample{{Iface: "wg3", PubKey: "GPUKEY", Rx: 1000, Tx: 20000, Handshake: later.Unix()}}, later, edgeFor)
	st.Record("gpu-01", []PeerSample{{Iface: "wg0", PubKey: "HUBKEY", Rx: 20000, Tx: 1000, Handshake: later.Unix()}}, later, edgeFor)

	st.mu.Lock()
	got := st.stats["gw|A|B"]
	st.mu.Unlock()

	if len(got.Sides) != 2 {
		t.Fatalf("stat holds %d sides, want both ends: %+v", len(got.Sides), got.Sides)
	}
	hub, gpu := got.Sides["wg-hub"], got.Sides["gpu-01"]
	if hub.TxPS <= hub.RxPS {
		t.Errorf("hub side lost its own direction: rx=%v tx=%v", hub.RxPS, hub.TxPS)
	}
	if gpu.RxPS <= gpu.TxPS {
		t.Errorf("gpu side lost its own direction: rx=%v tx=%v", gpu.RxPS, gpu.TxPS)
	}
	// The two ends measure the same bytes from opposite directions, which is
	// what makes the pair checkable.
	if hub.TxPS != gpu.RxPS || hub.RxPS != gpu.TxPS {
		t.Errorf("the two ends disagree about the same bytes: hub=%+v gpu=%+v", hub, gpu)
	}
}

// A side that has not been polled yet reports zero. Taking that as the tunnel's
// rate would draw a busy tunnel as dead.
func TestFlattenSidesIgnoresAnUnpolledSide(t *testing.T) {
	rx, tx, hs := flattenSides(map[string]EdgeSideStat{
		"polled":   {RxPS: 100, TxPS: 200, HS: 30},
		"unpolled": {HS: -1},
	})
	if rx != 100 || tx != 200 {
		t.Errorf("rates = %v/%v, want the polled side's", rx, tx)
	}
	// Handshake is a property of the tunnel, so the fresher observation wins and
	// "never" loses to any real value.
	if hs != 30 {
		t.Errorf("handshake = %d, want the one side that has seen one", hs)
	}
}

func TestFlattenSidesTakesTheMostRecentHandshake(t *testing.T) {
	_, _, hs := flattenSides(map[string]EdgeSideStat{
		"a": {HS: 300},
		"b": {HS: 12},
	})
	if hs != 12 {
		t.Errorf("handshake = %d, want the most recent (12)", hs)
	}
}
