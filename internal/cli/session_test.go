package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func TestSessionDetailTruncatesLongExecByDefault(t *testing.T) {
	e := store.KernelEvent{
		Kind:   "exec",
		Binary: "/usr/libexec/crio/conmon",
		Args:   strings.Repeat("0123456789", 30),
	}

	got := detail(e, sessionDetailOptions{Width: 40})
	if len([]rune(got)) != 40 {
		t.Fatalf("detail length = %d, want 40: %q", len([]rune(got)), got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("detail = %q, want ellipsis suffix", got)
	}
}

func TestSessionDetailFullKeepsLongExec(t *testing.T) {
	wantArgs := strings.Repeat("0123456789", 30)
	e := store.KernelEvent{
		Kind:   "exec",
		Binary: "/usr/libexec/crio/conmon",
		Args:   wantArgs,
	}

	got := detail(e, sessionDetailOptions{Full: true, Width: 40})
	if !strings.Contains(got, wantArgs) {
		t.Fatalf("detail = %q, want full args", got)
	}
	if strings.HasSuffix(got, "...") {
		t.Fatalf("detail = %q, did not expect truncation", got)
	}
}

// A host whose clock led Postgres wrote sessions that ended before they began.
// The reader must never render that as negative arithmetic.
func TestSessionDurationFloorsClockSkewAtZero(t *testing.T) {
	start := time.Date(2026, 7, 21, 16, 16, 12, 0, time.UTC)
	end := start.Add(-3*time.Minute - 15*time.Second)

	if got := dur(start, &end); got != "0s" {
		t.Fatalf("dur = %q, want 0s", got)
	}
	if !skewedSession(store.AuditSession{StartedAt: start, EndedAt: &end}) {
		t.Fatal("skewedSession = false, want true for an end before the start")
	}
}

func TestSessionDurationKeepsOrdinaryLengths(t *testing.T) {
	start := time.Date(2026, 7, 21, 16, 31, 0, 0, time.UTC)
	end := start.Add(21 * time.Second)

	if got := dur(start, &end); got != "21s" {
		t.Fatalf("dur = %q, want 21s", got)
	}
	if skewedSession(store.AuditSession{StartedAt: start, EndedAt: &end}) {
		t.Fatal("skewedSession = true, want false for a normal session")
	}
	if got := dur(start, nil); got != "live" {
		t.Fatalf("dur(open session) = %q, want live", got)
	}
}
