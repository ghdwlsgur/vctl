package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
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
