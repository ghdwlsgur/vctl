// Package strutil holds tiny string helpers shared across packages.
package strutil

import (
	"fmt"
	"strings"
	"time"
)

// CompactDuration renders d as a single largest-unit value (e.g. "5s", "3m",
// "2h", "4d") for at-a-glance "last seen" columns. It lived in internal/ui,
// which made every package that formats an age — including domain code that
// never renders — link the terminal styling library for a pure formatter.
func CompactDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// OneLine flattens a multi-line message for a table row.
//
// Vault and the OpenStack SDK return errors several lines long — a URL, a
// status, a bulleted cause — and dropping one into a key/value row breaks the
// alignment for every row after it. The whole message is kept, on one line,
// because the useful part is usually the last clause.
func OneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// FirstNonEmpty returns the first non-empty argument, or "" if all are empty.
func FirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
