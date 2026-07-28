package invcache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// A snapshot that holds only grants is not usable inventory. Treating it as
// usable made an outage surface as "inventory is empty — run 'vctl sync'",
// sending the operator at the one command that cannot work during an outage.
func TestGrantsOnlySnapshotIsNotInventory(t *testing.T) {
	now := time.Now()
	var snap Snapshot
	snap.SetGrants("albert", []string{"ssh"}, now)

	if snap.HasInventory() {
		t.Fatal("a grants-only snapshot reports usable inventory")
	}
	if !snap.CapturedAt.IsZero() {
		t.Fatal("recording grants stamped the inventory capture time")
	}
}

// The same bug from the refresh side: a grants-only snapshot must not look
// freshly captured, or the refresh that would fill in the hosts decides it has
// nothing to do and the cache stays empty for a full refresh interval.
func TestGrantsOnlySnapshotStillNeedsRefresh(t *testing.T) {
	now := time.Now()
	var snap Snapshot
	snap.SetGrants("albert", []string{"ssh"}, now)

	if !snap.NeedsRefresh(now, 5*time.Minute) {
		t.Fatal("a snapshot with no hosts declined to refresh")
	}
}

func TestNeedsRefreshHonoursInterval(t *testing.T) {
	now := time.Now()
	snap := fixture()
	snap.SetInventory(snap.Servers, now.Add(-time.Minute))

	if snap.NeedsRefresh(now, 5*time.Minute) {
		t.Error("a one-minute-old snapshot wanted a refresh at a 5m interval")
	}
	if !snap.NeedsRefresh(now, 30*time.Second) {
		t.Error("a one-minute-old snapshot declined a refresh at a 30s interval")
	}
}

// Host topology drifts; an address that pointed at one machine last month can
// point at another today. Past the limit the snapshot must be refused rather
// than used to route an operator.
func TestExpiredSnapshotIsRefused(t *testing.T) {
	now := time.Now()
	snap := fixture()
	snap.SetInventory(snap.Servers, now.Add(-40*24*time.Hour))

	if !snap.Expired(now, 30*24*time.Hour) {
		t.Error("a 40-day-old snapshot was not considered expired at a 30-day limit")
	}
	if snap.Expired(now, 0) {
		t.Error("a zero limit did not disable expiry")
	}

	fresh := fixture()
	fresh.SetInventory(fresh.Servers, now.Add(-time.Hour))
	if fresh.Expired(now, 30*24*time.Hour) {
		t.Error("an hour-old snapshot was considered expired")
	}
}

// Postgres answering with zero hosts is indistinguishable from a misconfigured
// read. Storing it would replace a working offline fallback with a dead one.
func TestCaptureRefusesEmptyResult(t *testing.T) {
	snap := fixture()
	before := len(snap.Servers)

	err := Capture(context.Background(), emptyReader{}, snap, time.Now())
	if err == nil {
		t.Fatal("capturing an empty inventory succeeded")
	}
	if len(snap.Servers) != before {
		t.Fatalf("a refused capture still modified the snapshot (%d hosts)", len(snap.Servers))
	}
}

// Update is the only sanctioned mutation path; it must create a snapshot when
// none exists and leave the file alone when fn declines.
func TestUpdateCreatesAndSkips(t *testing.T) {
	f := &FileStore{Path: t.TempDir() + "/inventory.json"}

	if err := f.Update(func(s *Snapshot) error {
		s.SetGrants("albert", []string{"ssh"}, time.Now())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, err := f.Load()
	if err != nil {
		t.Fatalf("Update did not create a snapshot: %v", err)
	}
	if _, ok := got.Grant("albert"); !ok {
		t.Fatal("Update did not persist the grant")
	}

	sentinel := errors.New("skip")
	if err := f.Update(func(s *Snapshot) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("Update swallowed fn's error: %v", err)
	}
	// The declined update must not have wiped what was there.
	if got, err := f.Load(); err != nil {
		t.Fatal(err)
	} else if _, ok := got.Grant("albert"); !ok {
		t.Fatal("a declined Update destroyed the stored grant")
	}
}

// An inventory refresh must not revoke offline authorization, and recording
// grants must not disturb the captured hosts.
func TestUpdatePreservesTheOtherHalf(t *testing.T) {
	f := &FileStore{Path: t.TempDir() + "/inventory.json"}
	now := time.Now()

	if err := f.Update(func(s *Snapshot) error {
		s.SetGrants("albert", []string{"ssh"}, now)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.Update(func(s *Snapshot) error {
		return Capture(context.Background(), NewMemory(fixture()), s, now)
	}); err != nil {
		t.Fatal(err)
	}

	got, err := f.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.HasInventory() {
		t.Error("capture did not land")
	}
	if _, ok := got.Grant("albert"); !ok {
		t.Error("capturing inventory dropped the cached grant")
	}
}

type emptyReader struct{ Reader }

func (emptyReader) ListWithStatus(context.Context, string) ([]store.ServerWithStatus, error) {
	return nil, nil
}
