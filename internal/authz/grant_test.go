package authz

import (
	"testing"
	"time"
)

// The expiry rule has one owner. `vctl cache status` renders its verdict by
// calling these, so a change here moves the gate and the report together.
func TestCachedGrantExpiry(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	window := 24 * time.Hour

	fresh := CachedGrant{Commands: []string{"ssh"}, ConfirmedAt: now.Add(-time.Hour)}
	if fresh.Expired(now, window) {
		t.Error("an hour-old grant expired inside a 24h window")
	}
	if got := fresh.Age(now); got != time.Hour {
		t.Errorf("Age = %v, want 1h", got)
	}

	stale := CachedGrant{Commands: []string{"ssh"}, ConfirmedAt: now.Add(-48 * time.Hour)}
	if !stale.Expired(now, window) {
		t.Error("a 48h-old grant survived a 24h window")
	}

	// A window of zero means offline authorization is switched off, which has to
	// read as expired rather than as "never expires".
	if !fresh.Expired(now, 0) {
		t.Error("a zero window did not expire a grant")
	}
	if !fresh.Expired(now, -time.Hour) {
		t.Error("a negative window did not expire a grant")
	}
}

// A confirmation stamped in the future is a skewed clock or an edited cache.
// Age clamps so the reported value stays sane; it must not become a way to make
// a grant permanent, which is why Expired never consults the raw difference.
func TestCachedGrantFutureStampClamps(t *testing.T) {
	now := time.Now()
	future := CachedGrant{Commands: []string{"ssh"}, ConfirmedAt: now.Add(72 * time.Hour)}

	if got := future.Age(now); got != 0 {
		t.Errorf("Age = %v, want 0 for a future stamp", got)
	}
	if future.Expired(now, 0) == false {
		t.Error("a future stamp survived a disabled offline window")
	}
}
