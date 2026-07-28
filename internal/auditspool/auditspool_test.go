package auditspool

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func newSpool(t *testing.T) *Spool {
	t.Helper()
	return &Spool{Path: filepath.Join(t.TempDir(), "spool", "access.jsonl"), MaxBytes: DefaultMaxBytes}
}

type recordingSink struct {
	got     []store.AccessEntry
	failAt  int // fail the Nth call (1-based); 0 never fails
	callNum int
}

func (r *recordingSink) LogAccess(_ context.Context, e store.AccessEntry) error {
	r.callNum++
	if r.failAt > 0 && r.callNum >= r.failAt {
		return errors.New("postgres gone again")
	}
	r.got = append(r.got, e)
	return nil
}

func TestAppendThenDrain(t *testing.T) {
	s := newSpool(t)
	for _, host := range []string{"host-a", "host-b"} {
		if err := s.Append(store.AccessEntry{Hostname: host, VaultUser: "albert", OK: true}); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := s.Pending(); n != 2 {
		t.Fatalf("pending = %d, want 2", n)
	}

	sink := &recordingSink{}
	sent, err := s.Drain(context.Background(), sink)
	if err != nil || sent != 2 {
		t.Fatalf("Drain = %d, %v", sent, err)
	}
	if n, _ := s.Pending(); n != 0 {
		t.Fatalf("%d records left after a full drain", n)
	}
	if sink.got[0].Hostname != "host-a" || sink.got[1].Hostname != "host-b" {
		t.Fatalf("replay order = %+v", sink.got)
	}
}

// The point of the spool is that an outage does not erase the trail, so the
// replayed row must carry the time of the connection, not the time of the
// flush. Otherwise a day of access collapses into one timestamp.
func TestAppendStampsConnectionTime(t *testing.T) {
	s := newSpool(t)
	before := time.Now().Add(-time.Second)
	if err := s.Append(store.AccessEntry{Hostname: "host-a"}); err != nil {
		t.Fatal(err)
	}

	sink := &recordingSink{}
	if _, err := s.Drain(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	got := sink.got[0].SignedAt
	if got.IsZero() {
		t.Fatal("replayed record has no timestamp — the audit row would be stamped at flush time")
	}
	if got.Before(before) || got.After(time.Now().Add(time.Second)) {
		t.Fatalf("SignedAt = %v, want the time of the Append", got)
	}
}

// A caller-supplied timestamp wins: the record already knows when it happened.
func TestAppendPreservesExplicitTime(t *testing.T) {
	s := newSpool(t)
	want := time.Date(2026, 7, 19, 3, 14, 0, 0, time.UTC)
	if err := s.Append(store.AccessEntry{Hostname: "host-a", SignedAt: want}); err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	if _, err := s.Drain(context.Background(), sink); err != nil {
		t.Fatal(err)
	}
	if !sink.got[0].SignedAt.Equal(want) {
		t.Fatalf("SignedAt = %v, want %v", sink.got[0].SignedAt, want)
	}
}

// A database that disappears mid-flush must cost nothing: what was written stays
// written, and what was not stays queued for the next attempt.
func TestDrainResumesAfterMidFlushFailure(t *testing.T) {
	s := newSpool(t)
	for _, host := range []string{"a", "b", "c"} {
		if err := s.Append(store.AccessEntry{Hostname: host}); err != nil {
			t.Fatal(err)
		}
	}

	sink := &recordingSink{failAt: 2}
	sent, err := s.Drain(context.Background(), sink)
	if err == nil {
		t.Fatal("a mid-flush failure was not reported")
	}
	if sent != 1 {
		t.Fatalf("sent = %d, want 1 before the failure", sent)
	}
	if n, _ := s.Pending(); n != 2 {
		t.Fatalf("pending = %d, want the 2 unflushed records to remain", n)
	}

	// Second attempt against a working sink drains the remainder in order.
	good := &recordingSink{}
	sent, err = s.Drain(context.Background(), good)
	if err != nil || sent != 2 {
		t.Fatalf("resumed Drain = %d, %v", sent, err)
	}
	if good.got[0].Hostname != "b" || good.got[1].Hostname != "c" {
		t.Fatalf("resumed order = %+v", good.got)
	}
}

// Losing one record to a crash mid-append must not block every record behind it.
func TestLoadSkipsCorruptLine(t *testing.T) {
	s := newSpool(t)
	if err := s.Append(store.AccessEntry{Hostname: "good-1"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{\"Hostname\":\"trunc\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := s.Append(store.AccessEntry{Hostname: "good-2"}); err != nil {
		t.Fatal(err)
	}

	sink := &recordingSink{}
	sent, err := s.Drain(context.Background(), sink)
	if err != nil {
		t.Fatal(err)
	}
	if sent != 2 {
		t.Fatalf("sent = %d, want the 2 intact records", sent)
	}
}

// The cap refuses new records rather than evicting old ones, and says so — a
// silent drop would look exactly like a successful write.
func TestFullSpoolRefusesVisibly(t *testing.T) {
	s := newSpool(t)
	s.MaxBytes = 200
	var lastErr error
	for range 50 {
		if err := s.Append(store.AccessEntry{Hostname: "host", Error: strings.Repeat("x", 40)}); err != nil {
			lastErr = err
			break
		}
	}
	if lastErr == nil {
		t.Fatal("the cap never triggered")
	}
	if !errors.Is(lastErr, ErrFull) {
		t.Fatalf("error = %v, want ErrFull", lastErr)
	}
	// Everything accepted before the cap is still there.
	if n, _ := s.Pending(); n == 0 {
		t.Fatal("hitting the cap discarded the records already queued")
	}
}

// The race that motivates claim-then-drain: another vctl process records an
// access while a flush is in flight. Read-send-rewrite would overwrite the new
// record with the pre-flush remainder and lose it silently.
func TestConcurrentAppendSurvivesDrain(t *testing.T) {
	s := newSpool(t)
	for _, host := range []string{"a", "b"} {
		if err := s.Append(store.AccessEntry{Hostname: host}); err != nil {
			t.Fatal(err)
		}
	}

	// appendingSink stands in for the interleaving: the moment the drain starts
	// sending, a concurrent command queues another record.
	sink := &recordingSink{}
	racing := sinkFunc(func(ctx context.Context, e store.AccessEntry) error {
		if e.Hostname == "a" {
			if err := s.Append(store.AccessEntry{Hostname: "c"}); err != nil {
				t.Fatal(err)
			}
		}
		return sink.LogAccess(ctx, e)
	})

	sent, err := s.Drain(context.Background(), racing)
	if err != nil || sent != 2 {
		t.Fatalf("Drain = %d, %v", sent, err)
	}
	if n, _ := s.Pending(); n != 1 {
		t.Fatalf("pending = %d, want the record queued mid-flush to survive", n)
	}

	final := &recordingSink{}
	if _, err := s.Drain(context.Background(), final); err != nil {
		t.Fatal(err)
	}
	if len(final.got) != 1 || final.got[0].Hostname != "c" {
		t.Fatalf("second drain delivered %+v, want the mid-flush record", final.got)
	}
}

// A batch that failed partway must be retried before newly queued records, and
// must not be lost when new ones arrive behind it.
func TestFailedBatchIsRetriedFirst(t *testing.T) {
	s := newSpool(t)
	for _, host := range []string{"a", "b"} {
		if err := s.Append(store.AccessEntry{Hostname: host}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Drain(context.Background(), &recordingSink{failAt: 1}); err == nil {
		t.Fatal("a failing sink did not report an error")
	}
	if n, _ := s.Pending(); n != 2 {
		t.Fatalf("pending = %d after a fully failed drain, want 2", n)
	}

	if err := s.Append(store.AccessEntry{Hostname: "c"}); err != nil {
		t.Fatal(err)
	}
	good := &recordingSink{}
	sent, err := s.Drain(context.Background(), good)
	if err != nil || sent != 3 {
		t.Fatalf("Drain = %d, %v", sent, err)
	}
	got := []string{good.got[0].Hostname, good.got[1].Hostname, good.got[2].Hostname}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("replay order = %v, want the retried batch first", got)
	}
	if n, _ := s.Pending(); n != 0 {
		t.Fatalf("%d records left after a clean drain", n)
	}
}

type sinkFunc func(context.Context, store.AccessEntry) error

func (f sinkFunc) LogAccess(ctx context.Context, e store.AccessEntry) error { return f(ctx, e) }

func TestPendingAndDrainOnMissingSpool(t *testing.T) {
	s := newSpool(t)
	if n, err := s.Pending(); err != nil || n != 0 {
		t.Fatalf("Pending on a missing spool = %d, %v", n, err)
	}
	sink := &recordingSink{}
	if sent, err := s.Drain(context.Background(), sink); err != nil || sent != 0 {
		t.Fatalf("Drain on a missing spool = %d, %v", sent, err)
	}
}

// The spool is a map of internal hosts; it must not be world-readable.
func TestSpoolFileIsPrivate(t *testing.T) {
	s := newSpool(t)
	if err := s.Append(store.AccessEntry{Hostname: "host-a"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("spool mode = %04o, want 0600", perm)
	}
}
