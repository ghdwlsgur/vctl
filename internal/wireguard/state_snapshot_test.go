package wireguard

import "testing"

func TestLiveSnapshotDoesNotExposeMutableState(t *testing.T) {
	s := NewState()
	s.stats["edge"] = EdgeStat{Sides: map[string]EdgeSideStat{"host": {TxPS: 42}}}
	s.errs["host"] = "failed"
	s.drifted[TunnelKey{Host: "host"}] = DriftPeer{Host: "host", AllowedIPs: []string{"10.0.0.0/24"}}
	snap := s.Snapshot()
	snap.Edges["edge"].Sides["host"] = EdgeSideStat{TxPS: 99}
	snap.Errors["host"] = "changed"
	snap.Drift[0].AllowedIPs[0] = "changed"
	next := s.Snapshot()
	if next.Edges["edge"].Sides["host"].TxPS != 42 || next.Errors["host"] != "failed" || next.Drift[0].AllowedIPs[0] != "10.0.0.0/24" {
		t.Fatal("snapshot aliases live state")
	}
}
