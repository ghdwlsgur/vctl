package cli

import (
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func ev(pid int) store.KernelEvent {
	return store.KernelEvent{Hostname: "incheon-aio01", Kind: "exec", PID: pid, CgroupID: 4242}
}

// clock lets a test advance time without sleeping.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newTestHold(grace time.Duration, batch int) (*attributionHold, *clock) {
	c := &clock{t: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)}
	h := newAttributionHold(grace, batch)
	h.now = c.now
	return h, c
}

// holdAll is the flush where nothing attributed — the steady state on a host with
// no logins, and the case the buffer has to survive without growing. It delegates
// to the production method, which is also the database-error retry path.
func holdAll(h *attributionHold, offered []store.KernelEvent) {
	h.holdAll(offered)
}

// A failed database write must not drop the batch: holdAll re-holds every event
// so the next flush retries it, and each keeps its original wait time so a long
// outage still expires events on schedule instead of holding them forever.
func TestHoldAllReholdsEveryEventForRetry(t *testing.T) {
	h, c := newTestHold(30*time.Second, 200)

	offered := h.merge([]store.KernelEvent{ev(1), ev(2), ev(3)}) // first flush hands them out
	h.holdAll(offered)                                           // ...the write fails, re-hold all
	if h.Held() != 3 {
		t.Fatalf("held = %d after holdAll, want 3", h.Held())
	}
	again := h.merge(nil) // next flush pulls them back out
	if len(again) != 3 {
		t.Fatalf("retry flush offered %d, want the 3 re-held events", len(again))
	}
	h.holdAll(again) // still failing, still no session — re-hold what we pulled

	c.add(31 * time.Second)
	if out := h.merge(nil); len(out) != 0 {
		t.Fatalf("after the grace elapsed the flush offered %d, want 0", len(out))
	}
	if h.Dropped() != 3 {
		t.Fatalf("dropped = %d, want 3 once the grace ran out", h.Dropped())
	}
}

// The whole reason the buffer exists: a login's first exec reaches collect before
// watch-sessions has written the session row. Miss once, and the event must come
// back on the next flush rather than disappear.
func TestHoldRetriesAMissOnTheNextFlush(t *testing.T) {
	h, c := newTestHold(30*time.Second, 10)

	pending := h.merge([]store.KernelEvent{ev(1), ev(2)})
	if len(pending) != 2 {
		t.Fatalf("first flush offered %d events, want 2", len(pending))
	}
	holdAll(h, pending) // the session row does not exist yet

	c.add(3 * time.Second) // one flush interval
	pending = h.merge([]store.KernelEvent{ev(3)})
	if len(pending) != 3 {
		t.Fatalf("second flush offered %d events, want 3 (2 retried + 1 new)", len(pending))
	}
	if h.Dropped() != 0 {
		t.Fatalf("dropped %d events while still inside grace, want 0", h.Dropped())
	}
}

// Held events keep their original first-attempt time. If a retry reset the clock,
// a busy host would hold the same event forever and the cap would be the only
// thing bounding it.
func TestHoldGraceMeasuresFromFirstAttemptNotLastRetry(t *testing.T) {
	h, c := newTestHold(10*time.Second, 10)

	holdAll(h, h.merge([]store.KernelEvent{ev(1)}))
	for i := 0; i < 3; i++ {
		c.add(4 * time.Second) // 4s, 8s, 12s since the first attempt
		holdAll(h, h.merge(nil))
	}
	if h.Dropped() != 1 {
		t.Fatalf("dropped %d, want 1 — grace restarted on retry", h.Dropped())
	}
	if h.Held() != 0 {
		t.Fatalf("still holding %d events past grace", h.Held())
	}
}

// The realistic flush: the session row landed, so the login's events attribute
// and only the host's own churn misses. The one that attributed must leave, and
// the one that missed must keep the stamp it already had.
func TestHoldPartialAttributionKeepsOnlyTheMisses(t *testing.T) {
	h, c := newTestHold(10*time.Second, 10)

	first := h.merge([]store.KernelEvent{ev(1), ev(2)})
	holdAll(h, first) // both miss at t=0

	c.add(4 * time.Second)
	offered := h.merge([]store.KernelEvent{ev(3)}) // [ev1, ev2, ev3]
	h.hold(offered, []int{1})                      // ev1 and ev3 attributed; ev2 missed

	if h.Held() != 1 || h.events[0].PID != 2 {
		t.Fatalf("held %d events (first PID %d), want just ev(2)", h.Held(), h.events[0].PID)
	}
	// ev2's stamp is still t=0, so 7 more seconds must expire it.
	c.add(7 * time.Second)
	if pending := h.merge(nil); len(pending) != 0 {
		t.Fatalf("offered %d events, want 0 — ev(2) got a fresh stamp", len(pending))
	}
	if h.Dropped() != 1 {
		t.Fatalf("dropped %d, want 1", h.Dropped())
	}
}

// Past the grace an event is what it looks like: host activity belonging to no
// login. Dropping it is the point of the change, and it has to be counted so the
// summary can say how much was discarded.
func TestHoldDropsAfterGraceAndCounts(t *testing.T) {
	h, c := newTestHold(30*time.Second, 10)

	holdAll(h, h.merge([]store.KernelEvent{ev(1), ev(2), ev(3)}))
	c.add(31 * time.Second)

	if pending := h.merge(nil); len(pending) != 0 {
		t.Fatalf("offered %d expired events for insert, want 0", len(pending))
	}
	if h.Dropped() != 3 {
		t.Fatalf("dropped = %d, want 3", h.Dropped())
	}
}

// A host with no sessions at all misses on every event. Holding must stay bounded
// there — the collector runs under a hard MemoryMax.
func TestHoldCapsWhatItKeeps(t *testing.T) {
	h, _ := newTestHold(time.Hour, 10) // cap = 20 * batch = 200
	var burst []store.KernelEvent
	for i := 0; i < 500; i++ {
		burst = append(burst, ev(i))
	}
	holdAll(h, h.merge(burst))

	if h.Held() != 200 {
		t.Fatalf("held %d events, want the 200 cap", h.Held())
	}
	if h.Dropped() != 300 {
		t.Fatalf("dropped %d, want 300", h.Dropped())
	}
	// The newest survive: the oldest were closest to expiring anyway.
	if h.events[0].PID != 300 {
		t.Fatalf("kept from PID %d, want the newest 200 starting at 300", h.events[0].PID)
	}
}

// grace <= 0 means "do not hold at all". It must not degrade into holding
// forever, which is what a naive cutoff comparison would do.
func TestHoldWithoutGraceKeepsNothing(t *testing.T) {
	h, _ := newTestHold(0, 10)
	holdAll(h, h.merge([]store.KernelEvent{ev(1), ev(2)}))

	if pending := h.merge(nil); len(pending) != 0 {
		t.Fatalf("offered %d events with no grace, want 0", len(pending))
	}
	if h.Dropped() != 2 {
		t.Fatalf("dropped = %d, want 2", h.Dropped())
	}
}

// drain hands back what is still held so shutdown can make one final attempt
// instead of discarding events whose session was about to land.
func TestHoldDrainReturnsWhatIsStillWaiting(t *testing.T) {
	h, _ := newTestHold(30*time.Second, 10)
	holdAll(h, h.merge([]store.KernelEvent{ev(1), ev(2)}))

	rest := h.drain()
	if len(rest) != 2 {
		t.Fatalf("drained %d, want 2", len(rest))
	}
	if h.Held() != 0 {
		t.Fatalf("still holding %d after drain", h.Held())
	}
}
