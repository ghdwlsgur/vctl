package cli

import (
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func TestTallyByDC(t *testing.T) {
	now := time.Now()
	fresh := &store.ServerStatus{LastSeenAt: now}                 // agent up
	stale := &store.ServerStatus{LastSeenAt: now.Add(-time.Hour)} // agent stale -> not up

	srv := func(dc string, st *store.ServerStatus, probe *time.Time) store.ServerWithStatus {
		return store.ServerWithStatus{
			Server: store.Server{DC: dc, LastSeenUp: probe},
			Status: st,
		}
	}

	servers := []store.ServerWithStatus{
		srv("seoul-onprem", fresh, nil), // up (agent fresh)
		srv("seoul-onprem", nil, &now),  // up~ (probe)
		srv("seoul-onprem", stale, nil), // stale -> not counted up
		srv("seoul-onprem", nil, nil),   // down
		srv("incheon-vm", nil, &now),    // up~
	}

	got := tallyByDC(servers)
	// first-seen order: seoul-onprem appears before incheon-vm in the input.
	want := []dcTally{
		{DC: "seoul-onprem", Up: 2, Total: 4}, // 4 hosts, 2 reachable (up + up~)
		{DC: "incheon-vm", Up: 1, Total: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("tally = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tally[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}
