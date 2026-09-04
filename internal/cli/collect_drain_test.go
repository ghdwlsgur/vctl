package cli

import (
	"context"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// modeIngestor records which insert the drain reached for.
type modeIngestor struct {
	plain, attributed int
}

func (m *modeIngestor) RecordSession(context.Context, store.AuditSession) (int64, error) {
	return 0, nil
}
func (m *modeIngestor) EndSession(context.Context, int64, time.Time, string) error { return nil }
func (m *modeIngestor) UnendedSessions(context.Context, string) ([]store.AuditSession, error) {
	return nil, nil
}
func (m *modeIngestor) InsertKernelEvents(_ context.Context, evs []store.KernelEvent) (int, error) {
	m.plain++
	return len(evs), nil
}
func (m *modeIngestor) InsertKernelEventsAttributed(_ context.Context, evs []store.KernelEvent) (int, []int, error) {
	m.attributed++
	return len(evs), nil, nil
}

// The final drain writes under the mode in force. Without --require-session
// every held event is stored; with it the attributed insert decides. The
// end-of-input path once used the attributed insert regardless, so a batch
// re-held after a failed write was silently skipped at EOF in the very mode
// whose contract is "capture everything".
func TestDrainHeldFollowsTheMode(t *testing.T) {
	for _, tc := range []struct {
		requireSession    bool
		plain, attributed int
	}{
		{requireSession: false, plain: 1, attributed: 0},
		{requireSession: true, plain: 0, attributed: 1},
	} {
		held := newAttributionHold(time.Hour, 8)
		held.holdAll([]store.KernelEvent{{}, {}})
		ing := &modeIngestor{}
		n, err := drainHeld(context.Background(), held, ing, tc.requireSession)
		if err != nil || n != 2 {
			t.Fatalf("requireSession=%v: n=%d err=%v", tc.requireSession, n, err)
		}
		if ing.plain != tc.plain || ing.attributed != tc.attributed {
			t.Errorf("requireSession=%v: plain=%d attributed=%d, want %d/%d",
				tc.requireSession, ing.plain, ing.attributed, tc.plain, tc.attributed)
		}
	}
	// Nothing held is nothing written, under either mode.
	ing := &modeIngestor{}
	if n, err := drainHeld(context.Background(), newAttributionHold(time.Hour, 8), ing, false); n != 0 || err != nil || ing.plain+ing.attributed != 0 {
		t.Errorf("an empty hold reached the store: n=%d err=%v calls=%d", n, err, ing.plain+ing.attributed)
	}
}
