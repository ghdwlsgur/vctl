package cli

import (
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func TestDCTotalsRows(t *testing.T) {
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

	got := dcTotalsRows(servers)
	want := [][]string{
		{"incheon-vm", "1", "1"},
		{"seoul-onprem", "4", "2"}, // 4 hosts, 2 reachable (up + up~)
		{"total", "5", "3"},
	}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for i := range want {
		for j := range want[i] {
			if got[i][j] != want[i][j] {
				t.Errorf("row %d col %d = %q, want %q (full: %v)", i, j, got[i][j], want[i][j], got)
			}
		}
	}
}
