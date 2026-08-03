package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func appliedRows(names ...string) []store.AppliedMigration {
	at := time.Date(2026, 8, 3, 18, 20, 11, 0, time.Local)
	out := make([]store.AppliedMigration, 0, len(names))
	for i, n := range names {
		out = append(out, store.AppliedMigration{
			Version:   n,
			Checksum:  strings.Repeat("a", 64),
			AppliedAt: at.Add(time.Duration(i) * time.Minute),
		})
	}
	return out
}

// --status changes nothing, so it has to say what does. A pending count with no
// next step leaves the reader at a dead end.
func TestMigrationStatusNamesPendingFilesAndTheCommandThatRunsThem(t *testing.T) {
	var buf bytes.Buffer
	renderMigrationStatus(&buf,
		appliedRows("001_init.sql", "002_kernel_audit.sql"),
		[]string{"013_server_state.sql"})
	out := stripANSI(buf.String())

	for _, want := range []string{"001_init.sql", "002_kernel_audit.sql", "013_server_state.sql", "1 pending", "vctl migrate"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output does not mention %q:\n%s", want, out)
		}
	}
	// Applied rows carry when they landed. Without it the listing cannot
	// distinguish the schema this database grew up with from what a deploy added
	// ten minutes ago.
	if !strings.Contains(out, "2026-08-03 18:20:11") {
		t.Errorf("applied rows carry no timestamp:\n%s", out)
	}
}

func TestMigrationStatusSaysUpToDateWhenNothingIsPending(t *testing.T) {
	var buf bytes.Buffer
	renderMigrationStatus(&buf, appliedRows("001_init.sql"), nil)
	out := stripANSI(buf.String())

	if !strings.Contains(out, "up to date") {
		t.Errorf("output does not say the schema is current:\n%s", out)
	}
	// Nothing to run, so nothing should suggest running it.
	if strings.Contains(out, "vctl migrate") {
		t.Errorf("an up-to-date schema was told to migrate:\n%s", out)
	}
	if !strings.Contains(out, "1 applied") {
		t.Errorf("output does not count what is applied:\n%s", out)
	}
}

// A database no ledger-keeping build has touched reports everything pending and
// an empty ledger. "0 applied" alone would read as a broken database rather
// than one this scheme has not reached yet.
func TestMigrationStatusExplainsAnEmptyLedger(t *testing.T) {
	var buf bytes.Buffer
	renderMigrationStatus(&buf, nil, []string{"001_init.sql", "002_kernel_audit.sql"})
	out := stripANSI(buf.String())

	if !strings.Contains(out, "nothing recorded") {
		t.Errorf("output does not explain the empty ledger:\n%s", out)
	}
	if !strings.Contains(out, "2 pending") {
		t.Errorf("output does not count the pending files:\n%s", out)
	}
}

// The hostname of this command is the point: a schema change and an inventory
// refresh are separate operations with different blast radii. `sync --migrate`
// still works so runbooks do not break, but it is marked deprecated so nobody
// learns it fresh.
func TestSyncMigrateFlagIsDeprecatedButStillPresent(t *testing.T) {
	f := syncCmd().Flags().Lookup("migrate")
	if f == nil {
		t.Fatal("sync --migrate was removed rather than deprecated; runbooks would break")
	}
	if f.Deprecated == "" {
		t.Error("sync --migrate carries no deprecation notice")
	}
	if !strings.Contains(f.Deprecated, "vctl migrate") {
		t.Errorf("the notice %q does not name the command that replaces it", f.Deprecated)
	}
}

// --status must be answerable without the rights to change anything, which is
// why it is a flag on a read path rather than a separate gated command.
func TestMigrateCommandTakesNoArgumentsAndOffersStatus(t *testing.T) {
	cmd := migrateCmd()
	if err := cmd.Args(cmd, []string{"something"}); err == nil {
		t.Error("migrate accepted a positional argument")
	}
	if cmd.Flags().Lookup("status") == nil {
		t.Error("migrate has no --status flag")
	}
	if cmd.Annotations["rbac.command"] != "migrate" {
		t.Errorf("migrate is not gated: annotations = %v", cmd.Annotations)
	}
}
