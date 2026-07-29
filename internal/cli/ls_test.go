package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func TestRenderInventoryOmitsRuntimeStatus(t *testing.T) {
	servers := []store.InventoryRow{
		{Server: store.Server{Hostname: "host-a", IP: "192.0.2.1", User: "root", DC: "seoul"}, Addresses: []string{"192.0.2.1"}},
		{Server: store.Server{Hostname: "host-b", IP: "192.0.2.2", User: "root", DC: "seoul"}, Addresses: []string{"192.0.2.2"}},
	}

	var out strings.Builder
	renderInventory(&out, servers, false)
	got := out.String()
	for _, unwanted := range []string{" up", "down", "stale", "seen ", "●", "○"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("inventory contains runtime status %q:\n%s", unwanted, got)
		}
	}
	for _, wanted := range []string{"host-a", "host-b", "· 2 hosts", "2 hosts"} {
		if !strings.Contains(got, wanted) {
			t.Errorf("inventory missing %q:\n%s", wanted, got)
		}
	}
}

// A snapshot cannot answer "is this host up right now", so the listing must not
// imply an answer. Both the per-row agent cell and the footer have to say the
// data is local, or a stale inventory reads exactly like a live one.
func TestRenderInventoryFromCacheSuppressesLiveness(t *testing.T) {
	seen := time.Now().Add(-2 * time.Hour)
	servers := []store.InventoryRow{{
		Server:    store.Server{Hostname: "host-a", IP: "192.0.2.1", User: "root", DC: "seoul"},
		Addresses: []string{"192.0.2.1"},
		AgentSeen: &seen,
	}}

	var out strings.Builder
	renderInventory(&out, servers, true)
	got := stripANSI(out.String())

	for _, unwanted := range []string{"up", "down", "stale", "no-agent"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("cached listing claims liveness %q:\n%s", unwanted, got)
		}
	}
	if !strings.Contains(got, "local snapshot") {
		t.Errorf("cached listing does not disclose the snapshot:\n%s", got)
	}
}

func TestIPCellShowsMergedExtraAddresses(t *testing.T) {
	row := store.InventoryRow{
		Server:    store.Server{IP: "10.0.0.1"},
		Addresses: []string{"10.0.0.1", "10.0.0.2", "192.168.1.5"},
	}
	got := stripANSI(ipCell(row))
	for _, want := range []string{"10.0.0.1", "+10.0.0.2", "+192.168.1.5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("ipCell = %q, want to contain %q", got, want)
		}
	}

	solo := store.InventoryRow{Server: store.Server{IP: "10.0.0.9"}, Addresses: []string{"10.0.0.9"}}
	if got := ipCell(solo); strings.Contains(got, "+") {
		t.Fatalf("ipCell single address = %q, want no extras marker", got)
	}
}

// `vctl status` counted every host with a server_status row as "reporting",
// which survives the agent that wrote it. In production that read 48/122 while
// no agent had reported for two days. liveStatusText is the shared judgement
// `vctl list` already used, so both now answer the same question.
func TestLiveStatusTextDistinguishesFreshFromStale(t *testing.T) {
	fresh := time.Now().Add(-time.Minute)
	old := time.Now().Add(-48 * time.Hour)
	probed := time.Now().Add(-time.Hour)

	cases := []struct {
		name string
		in   store.ServerWithStatus
		want string
	}{
		{"agent reporting now", store.ServerWithStatus{
			Status: &store.ServerStatus{LastSeenAt: fresh}}, "up"},
		{"agent silent for two days", store.ServerWithStatus{
			Status: &store.ServerStatus{LastSeenAt: old}}, "stale"},
		{"no agent, but a sync probe saw it", store.ServerWithStatus{
			Server: store.Server{LastSeenUp: &probed}}, "up~"},
		{"no agent, never probed", store.ServerWithStatus{}, "down"},
	}
	for _, tc := range cases {
		if got := liveStatusText(tc.in); got != tc.want {
			t.Errorf("%s: liveStatusText = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The count status reports must move with freshness, not with the mere presence
// of a row — the regression this guards is a fleet of dead agents reading as
// healthy.
func TestAgentCoverageCountsOnlyLiveAgents(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour)
	servers := []store.ServerWithStatus{
		{Status: &store.ServerStatus{LastSeenAt: old}},
		{Status: &store.ServerStatus{LastSeenAt: old}},
		{Status: &store.ServerStatus{LastSeenAt: time.Now()}},
	}
	var live int
	for _, s := range servers {
		if liveStatusText(s) == "up" {
			live++
		}
	}
	if live != 1 {
		t.Fatalf("counted %d live agents, want 1 (two are two days stale)", live)
	}
	if agentCoverageState(len(servers), live) == ui.StateOK {
		t.Error("1 of 3 reporting should not read as OK")
	}
	if agentCoverageState(len(servers), 0) != ui.StateWarn {
		t.Error("zero reporting must warn")
	}
}
