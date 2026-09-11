package socks5

import (
	"testing"
	"time"
)

func TestTrackerIdleFollowsTheLastClient(t *testing.T) {
	start := time.Now().Add(-10 * time.Minute)
	var tr Tracker
	if idle, ok := tr.IdleSince(start, time.Now()); !ok || idle < 9*time.Minute {
		t.Fatalf("never used: idle=%s ok=%v, want ~10m", idle, ok)
	}
	tr.begin()
	if _, ok := tr.IdleSince(start, time.Now()); ok {
		t.Fatal("a connected client still counted as idle")
	}
	if tr.Open() != 1 {
		t.Fatalf("open=%d", tr.Open())
	}
	tr.end()
	if idle, ok := tr.IdleSince(start, time.Now()); !ok || idle > time.Second {
		t.Fatalf("just released: idle=%s ok=%v, want ~0", idle, ok)
	}
	var nilTr *Tracker
	nilTr.begin()
	nilTr.end()
	if _, ok := nilTr.IdleSince(start, time.Now()); !ok || nilTr.Open() != 0 {
		t.Fatal("nil tracker must count nothing and be idle")
	}
}
