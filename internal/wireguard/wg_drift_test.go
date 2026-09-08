package wireguard

import (
	"testing"
	"time"
)

// A peer added since the last `vctl wg sync` is on the wire but not in the
// graph. record used to drop it — "ignore until re-sync" — so with a six-day-old
// snapshot the view was blind to every new tunnel and said nothing about it.
func TestDriftReportsPeersMissingFromTheSnapshot(t *testing.T) {
	st := NewState()
	now := time.Now()
	edgeFor := map[TunnelKey]string{
		{"gw-a", "wg0", "KNOWN"}: "gw|A|B",
	}
	st.Record("gw-a", []PeerSample{
		{Iface: "wg0", PubKey: "KNOWN", Handshake: now.Unix()},
		{Iface: "wg0", PubKey: "BRANDNEW", Endpoint: "203.0.113.9:51820",
			AllowedIPs: []string{"10.9.0.0/24"}, Handshake: now.Unix()},
	}, now, edgeFor)

	drift := st.Snapshot().Drift
	if len(drift) != 1 {
		t.Fatalf("drift = %+v, want just the peer with no row behind it", drift)
	}
	got := drift[0]
	if got.PubKey != "BRANDNEW" || got.Host != "gw-a" || got.Iface != "wg0" {
		t.Errorf("drift entry does not identify the peer: %+v", got)
	}
	// The live poll carries the full peer definition, so the report can say where
	// it is and what it routes — enough to recognise it without a re-sync.
	if got.Endpoint != "203.0.113.9:51820" || len(got.AllowedIPs) != 1 {
		t.Errorf("drift entry lost the peer's definition: %+v", got)
	}
}

// A tunnel that is in the snapshot must never be reported as drift, however many
// times it is polled.
func TestDriftIgnoresPeersTheSnapshotAlreadyHas(t *testing.T) {
	st := NewState()
	now := time.Now()
	edgeFor := map[TunnelKey]string{{"gw-a", "wg0", "KNOWN"}: "gw|A|B"}
	for i := 0; i < 3; i++ {
		st.Record("gw-a", []PeerSample{{Iface: "wg0", PubKey: "KNOWN", Handshake: now.Unix()}},
			now.Add(time.Duration(i)*time.Second), edgeFor)
	}
	if len(st.Snapshot().Drift) != 0 {
		t.Error("a peer that is in the snapshot was reported as drift")
	}
}

// A re-sync during a running session brings the peer into edgeFor. The notice
// has to clear, or it accumulates and stops meaning anything.
func TestDriftClearsOnceTheSnapshotCatchesUp(t *testing.T) {
	st := NewState()
	now := time.Now()
	before := map[TunnelKey]string{}
	st.Record("gw-a", []PeerSample{{Iface: "wg0", PubKey: "NEW", Handshake: now.Unix()}}, now, before)
	if len(st.Snapshot().Drift) == 0 {
		t.Fatal("the new peer was not reported at all")
	}

	after := map[TunnelKey]string{{"gw-a", "wg0", "NEW"}: "gw|A|B"}
	st.Record("gw-a", []PeerSample{{Iface: "wg0", PubKey: "NEW", Handshake: now.Unix()}}, now, after)
	if len(st.Snapshot().Drift) != 0 {
		t.Error("drift survived the snapshot catching up")
	}
}

// The list lands on screen, so its order has to be stable. An unstable order
// would reshuffle the view every two seconds and read as churn rather than as a
// fixed set of things to fix.
func TestDriftListIsOrderedStably(t *testing.T) {
	st := NewState()
	now := time.Now()
	st.Record("gw-b", []PeerSample{{Iface: "wg1", PubKey: "K2"}}, now, nil)
	st.Record("gw-a", []PeerSample{{Iface: "wg9", PubKey: "K3"}}, now, nil)
	st.Record("gw-a", []PeerSample{{Iface: "wg0", PubKey: "K1"}}, now, nil)

	st.mu.Lock()
	first := st.DriftList()
	second := st.DriftList()
	st.mu.Unlock()

	if len(first) != 3 {
		t.Fatalf("driftList = %d entries, want 3", len(first))
	}
	key := func(p DriftPeer) string { return p.Host + "/" + p.Iface + "/" + p.PubKey }
	for i := range first {
		if key(first[i]) != key(second[i]) {
			t.Fatalf("order is not stable at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
	if first[0].Host != "gw-a" || first[0].Iface != "wg0" {
		t.Errorf("not sorted by host then interface: %+v", first)
	}
}

// An idle state reports no drift at all, so a view can hide its notice rather
// than render an empty one.
func TestSnapshotHasNoDriftWhenThereIsNone(t *testing.T) {
	st := NewState()
	if d := st.Snapshot().Drift; len(d) != 0 {
		t.Errorf("an idle snapshot carries drift: %+v", d)
	}
}
