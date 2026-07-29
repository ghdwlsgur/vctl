package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// captureStderr runs fn with os.Stderr redirected, returning what was written.
// printAuditFootprint sends the warning there and the table to stdout, so the two
// have to be read separately.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = orig
	_ = w.Close()

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The exact shape that went unnoticed on 2026-07-29: kernel_event held 5,157 MB
// while the table was empty, and nothing anywhere said so. That is now a warning,
// and it names the command that reclaims it plus the cost of running it.
func TestFootprintWarnsOnParkedHighWaterMark(t *testing.T) {
	out := captureStderr(t, func() {
		if err := printAuditFootprint([]store.TableFootprint{
			{Table: "kernel_event", Bytes: 5157 * 1024 * 1024, Rows: 0, Dead: 0},
		}); err != nil {
			t.Fatal(err)
		}
	})

	for _, want := range []string{"kernel_event", "high-water mark", "VACUUM (FULL, ANALYZE) kernel_event", "exclusive lock"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q\ngot: %s", want, out)
		}
	}
}

// A big table that is big because it holds data is not bloat. Warning on it would
// train people to ignore the warning.
func TestFootprintStaysQuietWhenTheRowsJustifyTheSize(t *testing.T) {
	out := captureStderr(t, func() {
		if err := printAuditFootprint([]store.TableFootprint{
			{Table: "kernel_event", Bytes: 5157 * 1024 * 1024, Rows: 4_748_267, Dead: 0},
		}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "high-water mark") {
		t.Errorf("warned about a table whose rows justify its size:\n%s", out)
	}
}

// A small table must not warn either, whatever its row count.
func TestFootprintStaysQuietWhenSmall(t *testing.T) {
	out := captureStderr(t, func() {
		if err := printAuditFootprint([]store.TableFootprint{
			{Table: "kernel_event", Bytes: 48 * 1024, Rows: 0, Dead: 0},
			{Table: "audit_session", Bytes: 160 * 1024, Rows: 246, Dead: 0},
		}); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "high-water mark") {
		t.Errorf("warned about a small table:\n%s", out)
	}
}

// retention reports; it must never be able to delete. Class is what the gate
// reads, so pinning it here is what stops the command from quietly becoming a
// mutate again — and "prune" must be gone, not merely unused.
func TestRetentionIsGatedAsRead(t *testing.T) {
	class, ok := authz.ClassOf("retention")
	if !ok {
		t.Fatal("retention is not in the gated catalog")
	}
	if class != authz.ClassRead {
		t.Fatalf("retention class = %v, want ClassRead", class)
	}
	if _, ok := authz.ClassOf("prune"); ok {
		t.Fatal("prune is still in the gated catalog")
	}
}
