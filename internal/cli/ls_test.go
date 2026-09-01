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
	renderInventory(&out, servers, false, false)
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

func TestRenderInventoryHasCompactAndWideColumnContracts(t *testing.T) {
	seen := time.Now().Add(-time.Minute)
	servers := []store.InventoryRow{{
		Server: store.Server{
			Hostname: "host-a", IP: "192.0.2.1", User: "sre-admin", DC: "seoul",
			State: store.StateMaintenance,
		},
		Addresses: []string{"192.0.2.1"}, AgentSeen: &seen,
	}}

	var compact strings.Builder
	renderInventory(&compact, servers, false, false)
	compactText := ui.StripANSI(compact.String())
	for _, want := range []string{"HOST", "STATUS", "ADDRESS", "VIA", "up maint"} {
		if !strings.Contains(compactText, want) {
			t.Errorf("compact inventory missing %q:\n%s", want, compactText)
		}
	}
	if strings.Contains(compactText, "USER") {
		t.Errorf("compact inventory includes the wide-only USER column:\n%s", compactText)
	}

	var wide strings.Builder
	renderInventoryMode(&wide, servers, false, false, true)
	wideText := ui.StripANSI(wide.String())
	for _, want := range []string{"AGENT", "STATE", "USER", "sre-admin"} {
		if !strings.Contains(wideText, want) {
			t.Errorf("wide inventory missing %q:\n%s", want, wideText)
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
	renderInventory(&out, servers, true, false)
	got := ui.StripANSI(out.String())

	for _, unwanted := range []string{"up", "down", "stale", "no-agent"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("cached listing claims liveness %q:\n%s", unwanted, got)
		}
	}
	if !strings.Contains(got, "local snapshot") {
		t.Errorf("cached listing does not disclose the snapshot:\n%s", got)
	}
}

// The default listing shows one address and a count. Inlining every address
// made the column as wide as the most-homed host in the fleet, so single-homed
// rows carried ~150 characters of padding — the width is shared across all rows.
func TestIPCellCompactsExtraAddressesToACount(t *testing.T) {
	row := store.InventoryRow{
		Server:    store.Server{IP: "10.0.0.1"},
		Addresses: []string{"10.0.0.1", "10.0.0.2", "192.168.1.5"},
	}
	got := ui.StripANSI(ipCell(row, false))
	if !strings.Contains(got, "10.0.0.1") {
		t.Errorf("ipCell = %q, want the primary address", got)
	}
	if !strings.Contains(got, "(+2)") {
		t.Errorf("ipCell = %q, want the extras collapsed to (+2)", got)
	}
	// The point of collapsing is width. If an extra address still appears, the
	// column grows with the fleet's most-homed host all over again.
	for _, unwanted := range []string{"10.0.0.2", "192.168.1.5"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("ipCell = %q, still lists %q inline", got, unwanted)
		}
	}
}

// The addresses are collapsed, not dropped. --all-ips has to bring them back,
// because `vctl ssh --server <ip>` matches on them and an operator checking
// which address a host answers on needs to see the list.
func TestIPCellAllIPsListsEveryAddress(t *testing.T) {
	row := store.InventoryRow{
		Server:    store.Server{IP: "10.0.0.1"},
		Addresses: []string{"10.0.0.1", "10.0.0.2", "192.168.1.5"},
	}
	got := ui.StripANSI(ipCell(row, true))
	for _, want := range []string{"10.0.0.1", "+10.0.0.2", "+192.168.1.5"} {
		if !strings.Contains(got, want) {
			t.Fatalf("ipCell(all) = %q, want to contain %q", got, want)
		}
	}
}

// A single-homed host must not carry a marker at all: "(+0)" would be noise on
// most of the fleet, which is the problem this change exists to fix.
func TestIPCellSingleAddressHasNoMarker(t *testing.T) {
	solo := store.InventoryRow{Server: store.Server{IP: "10.0.0.9"}, Addresses: []string{"10.0.0.9"}}
	for _, all := range []bool{false, true} {
		if got := ui.StripANSI(ipCell(solo, all)); strings.ContainsAny(got, "+()") {
			t.Fatalf("ipCell(single, all=%v) = %q, want no extras marker", all, got)
		}
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
		// Unmanaged hosts get no verdict at all: up/down is a statement about
		// the node-agent, and the old probe fallback ("up~", then a red
		// "down") blamed appliances and never-onboarded machines for a daemon
		// they don't run.
		{"no agent, but a sync probe saw it", store.ServerWithStatus{
			Server: store.Server{LastSeenUp: &probed}}, ""},
		{"no agent, never probed", store.ServerWithStatus{}, ""},
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
}
