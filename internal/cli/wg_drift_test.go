package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A peer added since the last `vctl wg sync` is on the wire but not in the
// graph. record used to drop it — "ignore until re-serve" — so with a six-day-old
// snapshot the page was blind to every new tunnel and said nothing about it.
func TestDriftReportsPeersMissingFromTheSnapshot(t *testing.T) {
	st := newWGServeState()
	now := time.Now()
	edgeFor := map[tunnelKey]string{
		{"gw-a", "wg0", "KNOWN"}: "gw|A|B",
	}
	st.record("gw-a", []wgParsedPeer{
		{Iface: "wg0", PubKey: "KNOWN", Handshake: now.Unix()},
		{Iface: "wg0", PubKey: "BRANDNEW", Endpoint: "203.0.113.9:51820",
			AllowedIPs: []string{"10.9.0.0/24"}, Handshake: now.Unix()},
	}, now, edgeFor)

	var frame struct {
		Drift []wgDriftPeer `json:"drift"`
	}
	if err := json.Unmarshal(st.snapshotJSON(), &frame); err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if len(frame.Drift) != 1 {
		t.Fatalf("drift = %+v, want just the peer with no row behind it", frame.Drift)
	}
	got := frame.Drift[0]
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
	st := newWGServeState()
	now := time.Now()
	edgeFor := map[tunnelKey]string{{"gw-a", "wg0", "KNOWN"}: "gw|A|B"}
	for i := 0; i < 3; i++ {
		st.record("gw-a", []wgParsedPeer{{Iface: "wg0", PubKey: "KNOWN", Handshake: now.Unix()}},
			now.Add(time.Duration(i)*time.Second), edgeFor)
	}
	if strings.Contains(string(st.snapshotJSON()), "drift") {
		t.Error("a peer that is in the snapshot was reported as drift")
	}
}

// A re-sync during a running session brings the peer into edgeFor. The notice
// has to clear, or it accumulates and stops meaning anything.
func TestDriftClearsOnceTheSnapshotCatchesUp(t *testing.T) {
	st := newWGServeState()
	now := time.Now()
	before := map[tunnelKey]string{}
	st.record("gw-a", []wgParsedPeer{{Iface: "wg0", PubKey: "NEW", Handshake: now.Unix()}}, now, before)
	if !strings.Contains(string(st.snapshotJSON()), "drift") {
		t.Fatal("the new peer was not reported at all")
	}

	after := map[tunnelKey]string{{"gw-a", "wg0", "NEW"}: "gw|A|B"}
	st.record("gw-a", []wgParsedPeer{{Iface: "wg0", PubKey: "NEW", Handshake: now.Unix()}}, now, after)
	if strings.Contains(string(st.snapshotJSON()), "drift") {
		t.Error("drift survived the snapshot catching up")
	}
}

// The list lands on screen, so its order has to be stable. An unstable order
// would reshuffle the panel every two seconds and read as churn rather than as a
// fixed set of things to fix.
func TestDriftListIsOrderedStably(t *testing.T) {
	st := newWGServeState()
	now := time.Now()
	st.record("gw-b", []wgParsedPeer{{Iface: "wg1", PubKey: "K2"}}, now, nil)
	st.record("gw-a", []wgParsedPeer{{Iface: "wg9", PubKey: "K3"}}, now, nil)
	st.record("gw-a", []wgParsedPeer{{Iface: "wg0", PubKey: "K1"}}, now, nil)

	st.mu.Lock()
	first := st.driftList()
	second := st.driftList()
	st.mu.Unlock()

	if len(first) != 3 {
		t.Fatalf("driftList = %d entries, want 3", len(first))
	}
	key := func(p wgDriftPeer) string { return p.Host + "/" + p.Iface + "/" + p.PubKey }
	for i := range first {
		if key(first[i]) != key(second[i]) {
			t.Fatalf("order is not stable at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
	if first[0].Host != "gw-a" || first[0].Iface != "wg0" {
		t.Errorf("not sorted by host then interface: %+v", first)
	}
}

// An empty frame must not carry the key at all, so the page's panel stays hidden
// instead of rendering an empty box.
func TestFrameOmitsDriftWhenThereIsNone(t *testing.T) {
	st := newWGServeState()
	if strings.Contains(string(st.snapshotJSON()), "drift") {
		t.Error("an idle frame carries a drift key")
	}
}

// The page has to name the peers and say what to run. A count with no next step
// leaves the reader with a number and no action.
func TestDashboardDriftPanelSaysWhatToRun(t *testing.T) {
	got := runDashboardJS(t, `
let text="";
document.getElementById=()=>({set textContent(v){text=v}});
renderDrift([{host:"gw-a",iface:"wg0",pub:"ABCDEFGHIJKLMNOP",endpoint:"203.0.113.9:51820",allowed:["10.9.0.0/24"]}]);
console.log(text);
`)
	for _, want := range []string{"not in this snapshot", "gw-a/wg0", "203.0.113.9:51820", "10.9.0.0/24", "vctl wg sync"} {
		if !strings.Contains(got, want) {
			t.Errorf("drift panel does not mention %q:\n%s", want, got)
		}
	}
}

// Nothing to report means nothing on screen.
func TestDashboardDriftPanelIsEmptyWithNoDrift(t *testing.T) {
	got := runDashboardJS(t, `
let text="unset";
document.getElementById=()=>({set textContent(v){text=v}});
renderDrift([]);
console.log(JSON.stringify(text));
`)
	if got != `""` {
		t.Errorf("drift panel rendered %s with nothing to report", got)
	}
}
