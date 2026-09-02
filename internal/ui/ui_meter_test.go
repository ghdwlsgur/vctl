package ui

import (
	"strings"
	"testing"
)

// Meter is ten uncolored cells: full at 100, empty at 0, clamped outside, and
// rounded to the nearest cell in between.
func TestMeter(t *testing.T) {
	if got := Meter(0, 10); got != strings.Repeat("▱", 10) {
		t.Errorf("0%% = %q", got)
	}
	if got := Meter(100, 10); got != strings.Repeat("▰", 10) {
		t.Errorf("100%% = %q", got)
	}
	if got := Meter(52.3, 10); got != "▰▰▰▰▰▱▱▱▱▱" {
		t.Errorf("52.3%% = %q", got)
	}
	if got := Meter(140, 10); got != strings.Repeat("▰", 10) {
		t.Errorf("overflow = %q", got)
	}
	if got := Meter(-5, 10); got != strings.Repeat("▱", 10) {
		t.Errorf("negative = %q", got)
	}
	if got := Meter(50, 0); got != "" {
		t.Errorf("zero width = %q", got)
	}
}
