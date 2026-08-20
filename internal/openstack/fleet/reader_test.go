package fleet

import (
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
