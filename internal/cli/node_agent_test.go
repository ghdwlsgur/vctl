package cli

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/hoststatus"
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
//
// delay widens the window a second caller could slip through. Without it a
// concurrency test passes on timing rather than on the lock.
type opener struct {
	sinks []*fakeStatusSink
	errs  []error
	calls int
	delay time.Duration
}

func (o *opener) open(context.Context) (statusSink, error) {
	i := o.calls
	o.calls++
	if o.delay > 0 {
		time.Sleep(o.delay)
	}
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
	c := &statusConn{open: func(context.Context) (statusSink, error) { o.calls++; return sink, nil }}

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
	c := &statusConn{open: func(context.Context) (statusSink, error) { return sink, nil }}

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

// --once has to mean one of each. The probes run on their own goroutine in the
// long-running agent, and under --once the process exits as soon as the single
// heartbeat returns — a probe started in the background loses that race every
// time, and the command reported success having collected nothing.
//
// This pins the contract the fix rests on: with once set, the call collects
// before it returns.
func TestCapabilityProbesCollectBeforeReturningWhenOnce(t *testing.T) {
	sink := &fakeStatusSink{}
	conn := &statusConn{open: (&opener{sinks: []*fakeStatusSink{sink}}).open}

	runCapabilityProbes(context.Background(), conn, "host-01", time.Hour, true)

	if len(sink.caps) == 0 && len(sink.capErrors) == 0 {
		t.Fatal("nothing was reported by the time the call returned, so --once collects nothing")
	}
}

// A probe that cannot reach the database must not take the heartbeat with it.
// The agent's whole job is to keep saying the host is alive, and "we could not
// tell what it runs" is not a reason to stop.
func TestCapabilityProbeFailureLeavesTheHandleUsable(t *testing.T) {
	sink := &fakeStatusSink{err: errors.New("write failed")}
	conn := &statusConn{open: (&opener{sinks: []*fakeStatusSink{sink}}).open}

	runCapabilityProbes(context.Background(), conn, "host-01", time.Hour, true)

	if conn.st == nil {
		t.Error("a failed capability write dropped the connection the heartbeat shares")
	}
}

// The heartbeat and the capability probe are separate goroutines sharing one
// handle, and once an hour their ticks land together. Nothing in the suite ran
// them at the same time, which is why `-race` passed over an unsynchronised
// struct for as long as it did.
//
// Run under -race this fails without the mutex: the heartbeat writes c.st and
// c.healthy while the probe reads and writes c.st.
func TestHeartbeatAndCapabilityShareTheHandleSafely(t *testing.T) {
	sinks := make([]*fakeStatusSink, 64)
	for i := range sinks {
		sinks[i] = &fakeStatusSink{}
	}
	conn := &statusConn{open: (&opener{sinks: sinks}).open}
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = conn.report(ctx, "host-01") }()
		go func() {
			defer wg.Done()
			_ = conn.reportCapability(ctx, "host-01", hoststatus.ProbeResult{
				Kind: "openstack", Detected: true, Roles: []string{"compute"},
			})
		}()
	}
	wg.Wait()
}

// Two loops opening at the same moment left one pool and one Vault credential
// lease with nothing holding them: the second assignment overwrote the first,
// which was never closed. Once an hour, per host, against the central side.
func TestConcurrentFirstUseOpensOneConnection(t *testing.T) {
	o := &opener{sinks: []*fakeStatusSink{{}, {}}, delay: 20 * time.Millisecond}
	conn := &statusConn{open: o.open}
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = conn.report(ctx, "host-01") }()
	go func() {
		defer wg.Done()
		_ = conn.reportCapability(ctx, "host-01", hoststatus.ProbeResult{Kind: "openstack"})
	}()
	wg.Wait()

	if o.calls != 1 {
		t.Errorf("opened %d connections for one handle; the extra ones leak a pool and a Vault lease", o.calls)
	}
}

// A blackholed route does not fail, it hangs. Without a deadline the heartbeat
// stops forever while the process stays up, so systemd sees nothing wrong and
// the host goes quiet with no one told.
func TestAHangingDependencyDoesNotHangTheHeartbeat(t *testing.T) {
	conn := &statusConn{
		attempt: 50 * time.Millisecond,
		open: func(ctx context.Context) (statusSink, error) {
			<-ctx.Done() // never answers, like a connection into a blackhole
			return nil, ctx.Err()
		},
	}

	done := make(chan error, 1)
	go func() { done <- conn.report(context.Background(), "host-01") }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a dependency that never answered was reported as success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the heartbeat is still waiting; there is no per-attempt deadline")
	}
}

// The whole fleet is deployed in one pass, so without an offset every agent
// asks Vault and Postgres in the same second forever.
func TestJitterSpreadsTheFleetAndHoldsPerHost(t *testing.T) {
	const base = 5 * time.Minute

	// Same host, same answer: an offset redrawn on every restart just rolls
	// into a fresh collision.
	if a, b := jitterInterval(base, "sre-srv-0047"), jitterInterval(base, "sre-srv-0047"); a != b {
		t.Errorf("jitterInterval is not stable for one host: %v then %v", a, b)
	}
	seen := map[time.Duration]bool{}
	for _, h := range []string{"sre-srv-0047", "sre-srv-0048", "incheon-aio01", "incheon-gpu02"} {
		got := jitterInterval(base, h)
		if lo, hi := base-base/10, base+base/10; got < lo || got > hi {
			t.Errorf("jitterInterval(%s) = %v, outside %v..%v", h, got, lo, hi)
		}
		seen[got] = true
	}
	if len(seen) < 3 {
		t.Errorf("four hosts landed on %d distinct intervals; they are not being spread", len(seen))
	}
	// A host with no name has nothing to derive an offset from, and a probe
	// interval of 0 means "disabled" — neither may be turned into a schedule.
	if got := jitterInterval(base, ""); got != base {
		t.Errorf("jitterInterval with no hostname = %v, want the interval unchanged", got)
	}
	if got := jitterInterval(0, "sre-srv-0047"); got != 0 {
		t.Errorf("jitterInterval(0) = %v, want 0 to keep meaning disabled", got)
	}
}
