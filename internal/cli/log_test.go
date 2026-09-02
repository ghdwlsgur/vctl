package cli

import (
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The meter is ten cells with traffic lights at 75 and 90, and a missing
// measurement says so instead of pretending to be 0%.
func TestGaugeRow(t *testing.T) {
	if row := gaugeRow("Disk /", nil); row.Value != "not reported" {
		t.Errorf("nil pct = %q", row.Value)
	}
	v := 52.3
	row := gaugeRow("Memory", &v)
	if !strings.Contains(row.Value, "▰▰▰▰▰▱▱▱▱▱") || row.State != ui.StateOK {
		t.Errorf("52.3%% = %q state=%v", row.Value, row.State)
	}
	hot := 91.0
	if row := gaugeRow("Disk /", &hot); row.State != ui.StateFail {
		t.Errorf("91%% not critical: %v", row.State)
	}
	warm := 80.0
	if row := gaugeRow("Disk /", &warm); row.State != ui.StateWarn {
		t.Errorf("80%% not warned: %v", row.State)
	}
}

// The headline row's verdict must be liveStatusText's — the shared decision —
// with only the dressing (age, version, cached caveat) added here.
func TestAgentRowStates(t *testing.T) {
	fresh := &store.ServerWithStatus{Status: &store.ServerStatus{
		LastSeenAt: time.Now().Add(-time.Minute), AgentVersion: "0.4.10"}}
	if row := agentRow(fresh, false); row.State != ui.StateOK || !strings.Contains(row.Value, "up — reported") || !strings.Contains(row.Value, "0.4.10") {
		t.Errorf("fresh = %+v", row)
	}
	stale := &store.ServerWithStatus{Status: &store.ServerStatus{
		LastSeenAt: time.Now().Add(-48 * time.Hour)}}
	if row := agentRow(stale, false); row.State != ui.StateWarn || !strings.Contains(row.Value, "stale") {
		t.Errorf("stale = %+v", row)
	}
	if row := agentRow(fresh, true); row.State != ui.StateWarn || !strings.Contains(row.Value, "liveness unknown offline") {
		t.Errorf("cached = %+v", row)
	}
}
