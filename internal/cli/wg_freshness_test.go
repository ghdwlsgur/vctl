package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func ifaceAt(host, iface, key string, at time.Time) store.WGInterfaceRow {
	return store.WGInterfaceRow{
		WGInterface: store.WGInterface{Host: host, Iface: iface, PublicKey: key},
		CollectedAt: at,
	}
}

// The graph is drawn from a snapshot, and the page animates traffic on top of
// it. Without the snapshot's own timestamp the two are indistinguishable: the
// fleet this was written against had a six-day-old topology under a live-looking
// display, so every structural fact on screen was six days old while the page
// said it had just updated.
func TestTopologyCarriesTheCollectionTime(t *testing.T) {
	at := time.Date(2026, 7, 28, 9, 6, 45, 0, time.UTC)
	topo, _ := buildWGTopology(
		[]store.WGInterfaceRow{ifaceAt("gw-a", "wg0", "AKEY", at)},
		nil, nil, nil)

	if !topo.CollectedAt.Equal(at) {
		t.Errorf("CollectedAt = %v, want the row's collection time %v", topo.CollectedAt, at)
	}
}

// Newest, not oldest. Gateways are collected one after another and a host that
// failed its last sync keeps an older row, so the oldest would report the worst
// gateway's staleness rather than the snapshot's — and "how long ago was
// anything learned" is the question this answers.
func TestTopologyCollectedAtTakesTheNewestRow(t *testing.T) {
	old := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 7, 28, 9, 6, 45, 0, time.UTC)
	got := topologyCollectedAt([]store.WGInterfaceRow{
		ifaceAt("stuck-gw", "wg0", "OLD", old),
		ifaceAt("gw-a", "wg0", "AKEY", recent),
		ifaceAt("gw-b", "wg0", "BKEY", old),
	})
	if !got.Equal(recent) {
		t.Errorf("topologyCollectedAt = %v, want the newest row %v", got, recent)
	}
}

// No rows at all is a different statement from "collected at the epoch". The
// page renders zero as "never" and asks for a sync; a 1970 timestamp would
// render as an absurd age and read like a bug in the clock.
func TestTopologyCollectedAtIsZeroWithNoRows(t *testing.T) {
	if got := topologyCollectedAt(nil); !got.IsZero() {
		t.Errorf("topologyCollectedAt(nil) = %v, want the zero time", got)
	}
}

// The browser reads this field by name, so the JSON tag is part of the
// contract between the handler and the page.
func TestTopologyJSONExposesCollectedAt(t *testing.T) {
	at := time.Date(2026, 7, 28, 9, 6, 45, 0, time.UTC)
	topo, _ := buildWGTopology(
		[]store.WGInterfaceRow{ifaceAt("gw-a", "wg0", "AKEY", at)},
		nil, nil, nil)

	b, err := json.Marshal(topo)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		CollectedAt time.Time `json:"collectedAt"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.CollectedAt.Equal(at) {
		t.Errorf("collectedAt round-tripped as %v, want %v", got.CollectedAt, at)
	}
}

// The page has to show two clocks and label them apart. A single "Updated" is
// what made a stale graph read as current.
func TestDashboardSeparatesTopologyAndTelemetryClocks(t *testing.T) {
	page := string(wgServeHTML)
	for _, want := range []string{
		`id="topology-at"`, // structural age, from collectedAt
		`id="updated-at"`,  // live poll time
		">Topology<",
		">Telemetry<",
		"collectedAt",
		"TOPOLOGY_STALE_SECONDS",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard does not carry %q", want)
		}
	}
	// The old single-clock label would put the two facts back under one word.
	if strings.Contains(page, ">Updated<") {
		t.Error(`the dashboard still labels a clock "Updated"; that is the ambiguity this removes`)
	}
}
