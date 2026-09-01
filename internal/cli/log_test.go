package cli

import (
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
