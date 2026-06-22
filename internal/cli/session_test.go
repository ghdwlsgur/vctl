package cli

import (
	"strings"
	"testing"

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
