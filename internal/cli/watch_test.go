package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

type failingSessionStore struct {
	calls int
}

func (s *failingSessionStore) RecordSession(context.Context, store.AuditSession) (int64, error) {
	s.calls++
	return 0, errors.New("vault unavailable")
}

func (*failingSessionStore) EndSession(context.Context, int64, string) error { return nil }

func TestScanMarkersStopsAfterFirstBackendFailure(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		marker := sessionMarker{
			Serial:    "serial",
			Login:     "root",
			LeaderPID: 1000 + i,
			Host:      "gpu02",
			Started:   time.Now().UTC().Format(time.RFC3339),
		}
		b, err := json.Marshal(marker)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, string(rune('a'+i))+".json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	backend := &failingSessionStore{}
	err := scanMarkers(context.Background(), backend, dir, map[string]int64{})
	if err == nil {
		t.Fatal("scanMarkers succeeded, want backend error")
	}
	if backend.calls != 1 {
		t.Fatalf("RecordSession calls = %d, want 1", backend.calls)
	}
}

func TestWatchRetryLoopBacksOffAndResetsAfterSuccess(t *testing.T) {
	outcomes := []error{errors.New("vault unavailable"), errors.New("vault unavailable"), nil, errors.New("db unavailable")}
	var waits []time.Duration
	calls := 0

	err := runWatchLoop(
		context.Background(),
		10*time.Second,
		5*time.Minute,
		func() error {
			err := outcomes[calls]
			calls++
			return err
		},
		func(error) {},
		func(_ context.Context, delay time.Duration) bool {
			waits = append(waits, delay)
			return len(waits) < len(outcomes)
		},
	)
	if err != nil {
		t.Fatalf("runWatchLoop: %v", err)
	}

	want := []time.Duration{10 * time.Second, 20 * time.Second, 10 * time.Second, 10 * time.Second}
	if !reflect.DeepEqual(waits, want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
}

func TestWatchRetryLoopCapsBackoff(t *testing.T) {
	var waits []time.Duration
	err := runWatchLoop(
		context.Background(),
		10*time.Second,
		25*time.Second,
		func() error { return errors.New("vault unavailable") },
		func(error) {},
		func(_ context.Context, delay time.Duration) bool {
			waits = append(waits, delay)
			return len(waits) < 5
		},
	)
	if err != nil {
		t.Fatalf("runWatchLoop: %v", err)
	}

	want := []time.Duration{10 * time.Second, 20 * time.Second, 25 * time.Second, 25 * time.Second, 25 * time.Second}
	if !reflect.DeepEqual(waits, want) {
		t.Fatalf("waits = %v, want %v", waits, want)
	}
}

func TestJitterWatchDelayStaysWithinTwentyPercent(t *testing.T) {
	base := 5 * time.Minute
	for i := 0; i < 1000; i++ {
		got := jitterWatchDelay(base)
		if got < 4*time.Minute || got > 6*time.Minute {
			t.Fatalf("jitterWatchDelay(%s) = %s, want 4m..6m", base, got)
		}
	}
}
