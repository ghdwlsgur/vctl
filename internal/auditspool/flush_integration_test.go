package auditspool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// The unit tests replay into a fake sink, which proves the spool's bookkeeping
// but not that a queued record actually becomes an audit row. This drives the
// real path: queue while the database is unreachable, then flush into Postgres
// and read the rows back.
//
// Integration — needs VCTL_TEST_DSN pointing at a loopback Postgres.
func TestSpoolFlushesIntoPostgres(t *testing.T) {
	dsn := os.Getenv("VCTL_TEST_DSN")
	if dsn == "" {
		t.Skip("VCTL_TEST_DSN not set; skipping spool flush integration test")
	}
	ctx := context.Background()
	st, err := store.OpenLocal(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	host := "spool-flush-" + time.Now().UTC().Format("150405.000000")
	s := &Spool{Path: filepath.Join(t.TempDir(), "spool", "access.jsonl"), MaxBytes: DefaultMaxBytes}

	// Three connections during an outage, an hour apart, queued newest-last.
	base := time.Now().UTC().Add(-6 * time.Hour).Truncate(time.Second)
	for i, offset := range []time.Duration{0, time.Hour, 2 * time.Hour} {
		if err := s.Append(store.AccessEntry{
			VaultUser: "albert", Hostname: host,
			CertSerial: host + "-" + string(rune('a'+i)),
			OK:         true, SourceIP: "192.0.2.10", TargetAddr: "192.0.2.47:22",
			SignedAt: base.Add(offset),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if n, _ := s.Pending(); n != 3 {
		t.Fatalf("pending = %d, want 3", n)
	}

	sent, err := s.Drain(ctx, st)
	if err != nil || sent != 3 {
		t.Fatalf("Drain = %d, %v", sent, err)
	}
	if n, _ := s.Pending(); n != 0 {
		t.Fatalf("%d records left after a clean flush", n)
	}

	rows, err := st.AccessLog(ctx, 10, host, "", "")
	if err != nil {
		t.Fatalf("AccessLog: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("read back %d rows, want 3", len(rows))
	}

	// Each row must carry the time of its connection, not of the flush. Without
	// that, an outage's worth of access collapses onto the recovery moment.
	for i, want := range []time.Duration{2 * time.Hour, time.Hour, 0} {
		got := rows[i].SignedAt.UTC()
		if !got.Equal(base.Add(want)) {
			t.Errorf("row %d signed_at = %s, want %s", i, got, base.Add(want))
		}
		if rows[i].VaultUser != "albert" || rows[i].Hostname != host {
			t.Errorf("row %d lost its attribution: %+v", i, rows[i])
		}
		if rows[i].SourceIP != "192.0.2.10" {
			t.Errorf("row %d source_ip = %q, want the inet round-tripped", i, rows[i].SourceIP)
		}
	}

	// Nothing should have been stamped at flush time.
	for _, r := range rows {
		if time.Since(r.SignedAt) < time.Minute {
			t.Fatalf("a replayed row was stamped now (%s) — SignedAt was ignored", r.SignedAt)
		}
	}
}
