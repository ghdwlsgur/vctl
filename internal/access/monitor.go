package access

import (
	"context"
	"sync"
	"time"
)

// Monitor runs repeated polls against gateways for the live views
// (`vctl wg serve`, `vctl wg monitor`) and records transitions instead of
// polls.
//
// Why this is not just Execute on a timer: Execute audits every call, which is
// right for access — a command someone decided to run — and wrong for
// telemetry. `wg serve` polls every 2s per gateway, so three gateways write
// roughly 43,000 access_log rows a day. Production peaked at 87 rows/min while
// it was running. None of those rows record a decision anyone made, and all of
// them bury the rows that do.
//
// The failure case was worse than the volume. When the Vault session lapsed,
// every poll failed, every failure still tried to audit, every audit write also
// failed, and each one produced a warning — a line every couple of seconds per
// gateway, plus a spool entry, until the spool hit its cap and started
// reporting that too.
//
// So Monitor keeps the part of the guarantee that carries information and drops
// the part that only repeats: it records the first poll against a target, then
// every change in outcome — each failure, each recovery. A healthy session is
// one row. A flapping one is a row per flap, which is exactly what an operator
// or an auditor wants to see. What disappears is the steady state.
//
// The trade-off is real and worth naming: a row no longer tells you how long a
// monitoring session ran, only that it started and how it changed. Recording
// duration would need either a heartbeat (back to volume) or a column that
// says "this was monitoring", which the schema does not have. The volume was
// not buying that information either — 14,400 identical rows said nothing a
// single row does not.
type Monitor struct {
	conn *Connector

	mu   sync.Mutex
	seen map[string]pollOutcome
}

// pollOutcome is the last recorded result for one target.
type pollOutcome struct {
	ok bool
}

// Monitor returns a polling handle over this connector. Each handle keeps its
// own transition state, so one per monitoring session.
func (c *Connector) Monitor() *Monitor {
	return &Monitor{conn: c, seen: map[string]pollOutcome{}}
}

// Poll runs one monitoring command against a target. It returns exactly what
// Execute would; the difference is that the attempt is recorded only when it
// changes what the audit log already says.
func (m *Monitor) Poll(ctx context.Context, req Request, command string, timeout time.Duration) (Result, error) {
	res, entry, err := m.conn.run(ctx, req, command, timeout, nil)
	if m.shouldRecord(req.Target.Name, err == nil) {
		m.conn.record(ctx, entry)
	}
	return res, err
}

// shouldRecord reports whether this outcome is new information: the first poll
// against a target always is, and after that only a change of outcome is.
//
// Keyed on success alone, deliberately. Keying on the error text too would make
// a target that alternates between "i/o timeout" and "connection refused" write
// a row per poll again, which is the behaviour this exists to remove. The text
// of the current failure is still carried in the row written at the transition.
func (m *Monitor) shouldRecord(target string, ok bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, known := m.seen[target]
	m.seen[target] = pollOutcome{ok: ok}
	return !known || prev.ok != ok
}
