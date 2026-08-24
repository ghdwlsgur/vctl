package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func TestStoredReturnsAReadingWithItsProvenance(t *testing.T) {
	now := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	cache := NewCache(t.TempDir())
	if err := cache.Save(ShapeVMs, store.Fleet{
		ReadAt: now.Add(-2 * time.Minute),
		Deployments: []store.Deployment{
			{ID: "10.0.0.1:5000", DisplayName: "seoul-a"},
		},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}

	r := &Reader{Cache: cache, now: func() time.Time { return now }}
	got, ok := r.Stored(ShapeVMs, ForBrowsing)
	if !ok {
		t.Fatal("stored reading was not returned")
	}
	if got.Source != FromStored {
		t.Errorf("source = %s, want cache", got.Source)
	}
	if got.Age != 2*time.Minute {
		t.Errorf("age = %s, want 2m", got.Age)
	}
	farms := got.Catalog.Farms()
	if len(farms) != 1 || farms[0].Name != "seoul-a" {
		t.Fatalf("catalog farms = %v", farms)
	}
}

// The fallback widens the age window, not the audience. A purpose that may not
// read stored readings must get the database's error, not a stale reading
// relabelled as fallback — an address somebody is about to connect to may
// belong to a different machine by now.
func TestAPurposeThatMayNotReadStoredGetsTheErrorNotTheFallback(t *testing.T) {
	now := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
	cache := NewCache(t.TempDir())
	// Older than the fresh window, still inside the fallback window: the shape
	// where the fallback is the only way a stored reading could answer.
	if err := cache.Save(ShapeVMs, store.Fleet{
		ReadAt: now.Add(-2 * time.Hour),
		Deployments: []store.Deployment{
			{ID: "10.0.0.1:5000", DisplayName: "seoul-a"},
		},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	down := errors.New("database unreachable")
	r := &Reader{
		Cache: cache,
		Load:  func(context.Context) (store.Fleet, error) { return store.Fleet{}, down },
		now:   func() time.Time { return now },
	}

	if _, err := r.Read(context.Background(), ReadRequest{Shape: ShapeVMs, Purpose: ForConnecting}); !errors.Is(err, down) {
		t.Fatalf("ForConnecting was answered from disk during an outage: err = %v", err)
	}

	got, err := r.Read(context.Background(), ReadRequest{Shape: ShapeVMs, Purpose: ForListing})
	if err != nil {
		t.Fatalf("ForListing must still fall back: %v", err)
	}
	if got.Source != FromFallback || !errors.Is(got.Err, down) {
		t.Errorf("listing fallback = source %s, err %v; want fallback carrying the outage", got.Source, got.Err)
	}
}
