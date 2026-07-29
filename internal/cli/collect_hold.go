package cli

import (
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// attributionHold buffers kernel events that did not resolve to a session yet.
//
// Ingest cannot simply drop an unattributed event: Tetragon reports a login's
// first exec immediately, while the audit_session row it belongs to only appears
// once watch-sessions notices the PAM marker, up to its scan interval later. Drop
// on the first miss and every session loses exactly the commands most worth
// having — the ones typed first.
//
// So a miss is held and retried on later flushes. Only once an event has waited
// out the grace period without a session appearing is it treated as what it
// almost certainly is: host activity that belongs to no login (container and
// kubelet churn), which no future row will ever attribute.
type attributionHold struct {
	grace   time.Duration
	maxHeld int

	events  []store.KernelEvent
	firstAt []time.Time // when each held event was first attempted

	// offered carries the first-attempt stamps for the slice merge last handed
	// out, aligned by index. hold uses it to give a retried event back its
	// original stamp — without that the grace restarts on every retry and a host
	// with no sessions holds the same events until only the cap stops it.
	offered []time.Time

	dropped int
	now     func() time.Time // injectable for tests
}

// newAttributionHold caps the buffer relative to the flush batch. The cap matters
// on a busy host with no sessions at all, where every event is a miss: holding is
// bounded work, and the collector runs under a hard MemoryMax.
func newAttributionHold(grace time.Duration, batch int) *attributionHold {
	if batch <= 0 {
		batch = 200
	}
	return &attributionHold{
		grace:   grace,
		maxHeld: 20 * batch,
		now:     time.Now,
	}
}

// merge returns everything to attempt this flush: events held from earlier
// flushes whose grace has not expired, plus the new batch. Held events go first
// so the oldest get their retry before the buffer is trimmed again.
func (h *attributionHold) merge(fresh []store.KernelEvent) []store.KernelEvent {
	h.expire()
	now := h.now()
	out := make([]store.KernelEvent, 0, len(h.events)+len(fresh))
	h.offered = h.offered[:0]

	out = append(out, h.events...)
	h.offered = append(h.offered, h.firstAt...)
	out = append(out, fresh...)
	for range fresh {
		h.offered = append(h.offered, now)
	}

	h.events, h.firstAt = h.events[:0], h.firstAt[:0]
	return out
}

// hold records the events that came back unattributed, identified by their index
// in the slice merge handed out. An event already being held keeps its original
// first-attempt time, so the grace measures how long it has actually waited.
func (h *attributionHold) hold(offered []store.KernelEvent, missed []int) {
	for _, i := range missed {
		if i < 0 || i >= len(offered) {
			continue
		}
		stamp := h.now()
		if i < len(h.offered) {
			stamp = h.offered[i]
		}
		h.events = append(h.events, offered[i])
		h.firstAt = append(h.firstAt, stamp)
	}
	h.trim()
}

// expire drops held events whose grace has run out.
func (h *attributionHold) expire() {
	if h.grace <= 0 {
		h.dropped += len(h.events)
		h.events, h.firstAt = h.events[:0], h.firstAt[:0]
		return
	}
	cutoff := h.now().Add(-h.grace)
	keep := 0
	for i := range h.events {
		if h.firstAt[i].Before(cutoff) {
			h.dropped++
			continue
		}
		h.events[keep], h.firstAt[keep] = h.events[i], h.firstAt[i]
		keep++
	}
	h.events, h.firstAt = h.events[:keep], h.firstAt[:keep]
}

// trim enforces the cap by discarding the oldest held events, which are the ones
// closest to expiring anyway.
func (h *attributionHold) trim() {
	if over := len(h.events) - h.maxHeld; over > 0 {
		h.dropped += over
		h.events = append(h.events[:0], h.events[over:]...)
		h.firstAt = append(h.firstAt[:0], h.firstAt[over:]...)
	}
}

// Dropped is how many events were discarded as unattributable, for the summary.
func (h *attributionHold) Dropped() int { return h.dropped }

// Held is how many are still waiting for a session.
func (h *attributionHold) Held() int { return len(h.events) }

// drain returns whatever is still held, for a final attempt at shutdown.
func (h *attributionHold) drain() []store.KernelEvent {
	out := h.events
	h.events, h.firstAt = nil, nil
	return out
}
