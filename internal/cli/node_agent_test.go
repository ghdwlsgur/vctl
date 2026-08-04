package cli

import (
	"context"
	"errors"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// fakeStatusSink records what the agent did to it so a test can tell a reused
// handle from a reopened one.
type fakeStatusSink struct {
	upserts int
	closed  bool
	err     error

	caps      []store.Capability
	capErrors []string
}

func (f *fakeStatusSink) UpsertServerStatus(context.Context, store.ServerStatus) (bool, error) {
	f.upserts++
	if f.err != nil {
		return false, f.err
	}
	return true, nil
}

func (f *fakeStatusSink) UpsertCapability(_ context.Context, c store.Capability) (bool, error) {
	f.caps = append(f.caps, c)
	if f.err != nil {
		return false, f.err
	}
	return true, nil
}

func (f *fakeStatusSink) RecordCapabilityError(_ context.Context, _, kind, msg string) error {
	f.capErrors = append(f.capErrors, kind+": "+msg)
	return f.err
}

func (f *fakeStatusSink) Close() { f.closed = true }

// opener hands out sinks in order and counts how many times it was asked.
type opener struct {
	sinks []*fakeStatusSink
	errs  []error
	calls int
}

func (o *opener) open() (statusSink, error) {
	i := o.calls
	o.calls++
	if i < len(o.errs) && o.errs[i] != nil {
		return nil, o.errs[i]
	}
	return o.sinks[i], nil
}

// A dependency that is down when the agent starts must not be fatal: the next
// heartbeat has to try again. This is the case that took 33 hosts down on
// 2026-07-29 — the old code returned the open error out of RunE and the process
// exited before it ever reached its loop.
func TestStatusConnRetriesOpenAfterStartupFailure(t *testing.T) {
	sink := &fakeStatusSink{}
	o := &opener{errs: []error{errors.New("vault unavailable")}, sinks: []*fakeStatusSink{nil, sink}}
	c := &statusConn{open: o.open}

	if err := c.report(context.Background(), "sre-srv-0047"); err == nil {
		t.Fatal("first report succeeded, want the open error surfaced")
	}
	if c.st != nil {
		t.Fatal("a failed open left a handle behind")
	}
	if err := c.report(context.Background(), "sre-srv-0047"); err != nil {
		t.Fatalf("second report: %v", err)
	}
	if o.calls != 2 {
		t.Fatalf("open calls = %d, want 2 (retry after the failure)", o.calls)
	}
	if sink.upserts != 1 {
		t.Fatalf("upserts = %d, want 1", sink.upserts)
	}
}

// A failed heartbeat must drop the handle. Reopening re-runs the AppRole login
// and issues a fresh dynamic database credential; retrying on the old handle
// would keep using a lease that may already have lapsed.
func TestStatusConnReopensAfterReportFailure(t *testing.T) {
	broken := &fakeStatusSink{err: errors.New("db creds expired")}
	healthy := &fakeStatusSink{}
	o := &opener{sinks: []*fakeStatusSink{broken, healthy}}
	c := &statusConn{open: o.open}

	if err := c.report(context.Background(), "sre-srv-0047"); err == nil {
		t.Fatal("report succeeded, want the upsert error")
	}
	if !broken.closed {
		t.Fatal("failed handle was not closed")
	}
	if c.st != nil {
		t.Fatal("failed handle was retained")
	}
	if err := c.report(context.Background(), "sre-srv-0047"); err != nil {
		t.Fatalf("report after reconnect: %v", err)
	}
	if o.calls != 2 {
		t.Fatalf("open calls = %d, want 2", o.calls)
	}
}

// The healthy path must not churn connections: one open, many heartbeats.
func TestStatusConnReusesHandleWhileHealthy(t *testing.T) {
	sink := &fakeStatusSink{}
	o := &opener{sinks: []*fakeStatusSink{sink}}
	c := &statusConn{open: o.open}

	for i := 0; i < 3; i++ {
		if err := c.report(context.Background(), "sre-srv-0047"); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	if o.calls != 1 {
		t.Fatalf("open calls = %d, want 1", o.calls)
	}
	if sink.upserts != 3 {
		t.Fatalf("upserts = %d, want 3", sink.upserts)
	}
	if sink.closed {
		t.Fatal("handle closed while healthy")
	}

	c.close()
	if !sink.closed {
		t.Fatal("close() did not close the handle")
	}
}

// An unregistered host is a warning, not an error — and must not cost the
// connection. Losing it here would make every heartbeat reopen forever.
func TestStatusConnKeepsHandleWhenHostUnregistered(t *testing.T) {
	sink := &unregisteredSink{}
	o := &opener{sinks: []*fakeStatusSink{nil}}
	c := &statusConn{open: func() (statusSink, error) { o.calls++; return sink, nil }}

	if err := c.report(context.Background(), "not-in-inventory"); err != nil {
		t.Fatalf("report: %v", err)
	}
	if c.st == nil {
		t.Fatal("handle dropped for an unregistered host")
	}
	if sink.closed {
		t.Fatal("handle closed for an unregistered host")
	}
}

type unregisteredSink struct {
	closed  bool
	upserts int
}

func (u *unregisteredSink) UpsertServerStatus(context.Context, store.ServerStatus) (bool, error) {
	u.upserts++
	return false, nil
}

// The unregistered host's capability writes are refused the same way its
// heartbeat is: matched=false, no error.
func (u *unregisteredSink) UpsertCapability(context.Context, store.Capability) (bool, error) {
	return false, nil
}

func (u *unregisteredSink) RecordCapabilityError(context.Context, string, string, string) error {
	return nil
}

func (u *unregisteredSink) Close() { u.closed = true }

// Steady-state success must be silent. The agent reports every five minutes, so
// logging each success writes 288 lines a day per host to say nothing changed,
// and the failures worth reading get buried. `healthy` is what distinguishes a
// transition from a repeat, so it is asserted directly rather than through the
// log output.
func TestHealthyStaysSetWhileReportsKeepSucceeding(t *testing.T) {
	o := &opener{sinks: []*fakeStatusSink{{}}}
	c := &statusConn{open: o.open}
	ctx := context.Background()

	if c.healthy {
		t.Fatal("healthy is set before the first report: startup would be silent")
	}
	for i := 0; i < 3; i++ {
		if err := c.report(ctx, "host-a"); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
		if !c.healthy {
			t.Fatalf("healthy cleared after a successful report %d", i)
		}
	}
	if o.calls != 1 {
		t.Errorf("opened %d handles, want 1", o.calls)
	}
}

// A failure has to re-arm the transition, or the recovery goes unlogged and the
// operator sees the outage start but never its end.
func TestFailureReArmsTheSuccessLog(t *testing.T) {
	failing := &fakeStatusSink{err: errors.New("postgres is down")}
	o := &opener{sinks: []*fakeStatusSink{failing, {}}}
	c := &statusConn{open: o.open}
	ctx := context.Background()

	if err := c.report(ctx, "host-a"); err == nil {
		t.Fatal("report succeeded against a failing sink")
	}
	if c.healthy {
		t.Error("healthy is still set after a failure: the recovery would not be logged")
	}
	if err := c.report(ctx, "host-a"); err != nil {
		t.Fatalf("report after recovery: %v", err)
	}
	if !c.healthy {
		t.Error("healthy not set after recovery")
	}
}

// An unregistered host is a standing misconfiguration, not a working agent. It
// must not count as the success that silences later logging, or the one message
// explaining why no status ever appears would print once and never again.
func TestUnregisteredHostDoesNotCountAsHealthy(t *testing.T) {
	sink := &unregisteredSink{}
	c := &statusConn{open: func() (statusSink, error) { return sink, nil }}

	for i := 0; i < 2; i++ {
		if err := c.report(context.Background(), "ghost"); err != nil {
			t.Fatalf("report %d returned an error, want a warning only: %v", i, err)
		}
	}
	if c.healthy {
		t.Error("an ignored heartbeat marked the agent healthy")
	}
	if sink.upserts != 2 {
		t.Errorf("upserts = %d, want 2: the agent stopped trying", sink.upserts)
	}
}
