package store

import (
	"context"
	"testing"
	"time"
)

// The audit spool replays records long after the connection happened, so
// LogAccess has to honour an explicit SignedAt. Without it every record queued
// during an outage lands stamped with the moment connectivity returned, which
// collapses the outage window into a single timestamp and makes the access log
// lie about when people connected.
//
// Integration — needs VCTL_TEST_DSN.
func TestLogAccessHonoursExplicitSignedAt(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Truncated to microseconds: that is Postgres timestamptz resolution, so a
	// nanosecond-precision Go time would not round-trip equal.
	want := time.Date(2026, 7, 19, 3, 14, 15, 123456000, time.UTC)
	serial := "verify-explicit-" + time.Now().UTC().Format("150405.000000")

	if err := st.LogAccess(ctx, AccessEntry{
		VaultUser: "albert", Hostname: "sre-srv-0047", CertSerial: serial,
		OK: true, SignedAt: want,
	}); err != nil {
		t.Fatalf("LogAccess: %v", err)
	}

	var got time.Time
	if err := st.pool.QueryRow(ctx,
		`SELECT signed_at FROM access_log WHERE cert_serial=$1`, serial).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !got.UTC().Equal(want) {
		t.Fatalf("signed_at = %s, want the connection time %s", got.UTC(), want)
	}
}

// The live path leaves SignedAt zero and lets the database stamp the row. That
// must keep working — the coalesce has to fall through to now(), not insert a
// zero-value year-1 timestamp.
func TestLogAccessDefaultsSignedAtToNow(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	serial := "verify-default-" + time.Now().UTC().Format("150405.000000")
	before := time.Now().UTC().Add(-time.Minute)

	if err := st.LogAccess(ctx, AccessEntry{
		VaultUser: "albert", Hostname: "sre-srv-0047", CertSerial: serial, OK: true,
	}); err != nil {
		t.Fatalf("LogAccess: %v", err)
	}

	var got time.Time
	if err := st.pool.QueryRow(ctx,
		`SELECT signed_at FROM access_log WHERE cert_serial=$1`, serial).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	got = got.UTC()
	if got.Before(before) || got.After(time.Now().UTC().Add(time.Minute)) {
		t.Fatalf("signed_at = %s, want roughly now", got)
	}
	if got.Year() < 2000 {
		t.Fatalf("signed_at = %s — the zero time was inserted instead of now()", got)
	}
}

// AccessLog orders newest first by signed_at. A replayed record must therefore
// sort by when it happened, not by when it was inserted — the property that
// makes an out-of-order spool flush harmless.
func TestAccessLogOrdersReplayedRecordsByConnectionTime(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	host := "verify-order-" + time.Now().UTC().Format("150405.000000")
	base := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)

	// Insert out of order, exactly as a spool flush would after an outage.
	for _, offset := range []time.Duration{2 * time.Hour, 0, time.Hour} {
		if err := st.LogAccess(ctx, AccessEntry{
			Hostname: host, CertSerial: host + "-" + offset.String(),
			OK: true, SignedAt: base.Add(offset),
		}); err != nil {
			t.Fatalf("LogAccess: %v", err)
		}
	}

	rows, err := st.AccessLog(ctx, 10, host, "", "")
	if err != nil {
		t.Fatalf("AccessLog: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("read back %d rows, want 3", len(rows))
	}
	for i := 1; i < len(rows); i++ {
		if rows[i-1].SignedAt.Before(rows[i].SignedAt) {
			t.Fatalf("rows are not newest-first: %s then %s", rows[i-1].SignedAt, rows[i].SignedAt)
		}
	}
	if !rows[0].SignedAt.UTC().Equal(base.Add(2 * time.Hour)) {
		t.Fatalf("newest row = %s, want the latest connection time", rows[0].SignedAt.UTC())
	}
}
