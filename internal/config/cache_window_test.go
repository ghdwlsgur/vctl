package config

import (
	"testing"
	"time"
)

// The stale limit is a guard, and a guard set wide enough never to fire is not a
// guard. It was 30d, with a comment saying it was picked to "never bite in
// practice". These bounds exist so that framing cannot come back quietly: a
// snapshot refreshed hourly has no business routing an operator after a week, and
// nothing in this fleet needs a month.
func TestCacheStaleLimitStaysBounded(t *testing.T) {
	got := Defaults().CacheStaleLimit()
	if got != 7*24*time.Hour {
		t.Fatalf("compiled default = %v, want 168h", got)
	}
	if fallback := (&Config{}).CacheStaleLimit(); fallback != 7*24*time.Hour {
		t.Fatalf("unset fallback = %v, want 168h", fallback)
	}
}

// A malformed override must not widen the window. parseDurationOr exists for
// exactly this, and the stale limit is the value where getting it wrong is worst.
func TestCacheStaleLimitIgnoresJunkOverride(t *testing.T) {
	for _, bad := range []string{"", "forever", "-1h", "0h"} {
		c := &Config{CacheMaxAge: bad}
		if got := c.CacheStaleLimit(); got != 7*24*time.Hour {
			t.Errorf("CacheMaxAge=%q gave %v, want the 168h default", bad, got)
		}
	}
}

// "0" is the documented way to turn the limit off — it has to keep working, and
// it has to be the *only* thing that does.
func TestCacheStaleLimitZeroDisables(t *testing.T) {
	if got := (&Config{CacheMaxAge: "0"}).CacheStaleLimit(); got != 0 {
		t.Fatalf(`CacheMaxAge="0" gave %v, want 0 (disabled)`, got)
	}
	if got := (&Config{CacheMaxAge: " 0 "}).CacheStaleLimit(); got != 0 {
		t.Fatalf(`padded "0" gave %v, want 0 (disabled)`, got)
	}
}

// The stale limit must not fall below the offline authorization window, or
// shortening it would start refusing lookups that offline authz would still have
// allowed — a behavior change nobody asked for hiding inside a cache setting.
func TestCacheStaleLimitOutlivesOfflineWindow(t *testing.T) {
	d := Defaults()
	if d.CacheStaleLimit() <= d.CacheOfflineWindow() {
		t.Fatalf("stale limit %v must exceed offline window %v",
			d.CacheStaleLimit(), d.CacheOfflineWindow())
	}
}
