package cli

import (
	"context"
	"errors"
	"fmt"
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

func (f *fakeStatusSink) ReplaceCapabilities(_ context.Context, _, _ string, caps []store.Capability) (bool, error) {
	// The whole pass or none of it — the same all-or-nothing the transaction
	// gives, so a test cannot pass here and tear in production.
	if f.err != nil {
		return false, f.err
	}
	f.caps = append(f.caps, caps...)
	return true, nil
}

func (f *fakeStatusSink) RecordCapabilityError(_ context.Context, _, kind, msg string) error {
	f.capErrors = append(f.capErrors, kind+": "+msg)
	return f.err
}

func (f *fakeStatusSink) Close() { f.closed = true }

// opener hands out sinks in order and counts how many times it was asked.
//
// hold, when set, keeps the first open inside the call until the test closes
// it, and entered says when that has happened. That is the window a second
// caller would slip through without the lock: held open explicitly rather than
// for some duration a slow machine could outrun.
type opener struct {
	sinks   []*fakeStatusSink
	errs    []error
	calls   int
	hold    chan struct{}
	entered chan struct{}
}

func (o *opener) open(context.Context) (statusSink, error) {
	i := o.calls
	o.calls++
	if i == 0 && o.hold != nil {
		close(o.entered)
		<-o.hold
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
func (u *unregisteredSink) ReplaceCapabilities(context.Context, string, string, []store.Capability) (bool, error) {
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
	o := &opener{
		sinks:   []*fakeStatusSink{{}, {}},
		hold:    make(chan struct{}),
		entered: make(chan struct{}),
	}
	conn := &statusConn{open: o.open}
	ctx := context.Background()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = conn.report(ctx, "host-01") }()
	<-o.entered // the first caller is now inside open, and stays there

	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = conn.reportCapability(ctx, "host-01", hoststatus.ProbeResult{Kind: "openstack"})
	}()
	// Give the second caller time to reach either open (no lock) or the mutex
	// (locked). Only this hand-off needs waiting on; the window itself is held.
	time.Sleep(50 * time.Millisecond)
	close(o.hold)
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

// The whole fleet is deployed in one pass, so without an offset on the *first*
// run every agent reaches Vault in the same second.
//
// The offset goes on the first run and nowhere else. Skewing the recurring
// interval instead was the first attempt: it left the startup pile-up entirely
// untouched — both loops run once immediately, before any ticker exists — and
// made every host's heartbeat permanently something other than five minutes.
func TestStartPhaseSpreadsTheFleetWithoutMovingTheInterval(t *testing.T) {
	hosts := []string{"sre-srv-0047", "sre-srv-0048", "incheon-aio01", "incheon-gpu02", "sre-srv-0058"}

	// Same host, same answer: an offset redrawn on every restart just rolls
	// into a fresh collision, and "these two always land together" stops being
	// reproducible.
	if a, b := startPhase(heartbeatPhase, "sre-srv-0047", "heartbeat"), startPhase(heartbeatPhase, "sre-srv-0047", "heartbeat"); a != b {
		t.Errorf("startPhase is not stable for one host: %v then %v", a, b)
	}
	seen := map[time.Duration]bool{}
	for _, h := range hosts {
		got := startPhase(heartbeatPhase, h, "heartbeat")
		if got < 0 || got >= heartbeatPhase {
			t.Errorf("startPhase(%s) = %v, outside [0, %v)", h, got, heartbeatPhase)
		}
		seen[got] = true
	}
	if len(seen) < len(hosts)-1 {
		t.Errorf("%d hosts landed on %d distinct offsets; they are not being spread", len(hosts), len(seen))
	}
	// The offsets have to reach across the window, not merely stay inside it.
	//
	// Checking only the upper bound is what let a 32-bit hash through: a
	// Duration is a nanosecond count, FNV-32 tops out at 4294967295, and 4.29s
	// is under every window here — so `hash % window` did nothing and both
	// windows silently collapsed to [0, 4.29s), the capability probe's 70×
	// narrower than written. Every assertion still passed.
	for _, w := range []struct {
		name   string
		window time.Duration
		loop   string
	}{
		{"heartbeat", heartbeatPhase, "heartbeat"},
		{"capability", capabilityPhase, "capability"},
	} {
		var widest time.Duration
		for i := range 200 {
			if got := startPhase(w.window, fmt.Sprintf("sre-srv-%04d", i), w.loop); got > widest {
				widest = got
			}
		}
		if widest < w.window/2 {
			t.Errorf("%s: 200 hosts span only %v of a %v window; the offsets do not reach across it",
				w.name, widest, w.window)
		}
	}
	// The two loops on one host must not share an offset. With a single
	// per-host fraction the capability probe landed on exactly the same tick as
	// every twelfth heartbeat, on every host, forever.
	same := 0
	for _, h := range hosts {
		// Each loop's own window, which is what the agent actually asks for.
		// Comparing both against heartbeatPhase tested a schedule that does not
		// exist and would have missed the two windows being wired the same.
		if startPhase(heartbeatPhase, h, "heartbeat") == startPhase(capabilityPhase, h, "capability") {
			same++
		}
	}
	if same == len(hosts) {
		t.Error("both loops draw the same offset on every host; they are one clock, not two")
	}
	// No name to derive from, or no window to spread over: run now rather than
	// invent a schedule.
	if got := startPhase(heartbeatPhase, "", "heartbeat"); got != 0 {
		t.Errorf("startPhase with no hostname = %v, want 0", got)
	}
	if got := startPhase(0, "sre-srv-0047", "heartbeat"); got != 0 {
		t.Errorf("startPhase with no window = %v, want 0", got)
	}
}

// hangingSink blocks in whichever call the test names, until its context is
// cancelled. A sink that hangs is the realistic shape of a blackholed route:
// the connection was established, the query went out, nothing came back.
type hangingSink struct {
	on string // "status" | "capability" | "caperror"
}

func (h *hangingSink) block(ctx context.Context, which string) error {
	if h.on == which {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func (h *hangingSink) UpsertServerStatus(ctx context.Context, _ store.ServerStatus) (bool, error) {
	return true, h.block(ctx, "status")
}

func (h *hangingSink) ReplaceCapabilities(ctx context.Context, _, _ string, _ []store.Capability) (bool, error) {
	return true, h.block(ctx, "capability")
}

func (h *hangingSink) RecordCapabilityError(ctx context.Context, _, _, _ string) error {
	return h.block(ctx, "caperror")
}

func (h *hangingSink) Close() {}

// The deadline has to cover the writes, not just the open. An established
// connection whose query never returns is the same outage as one that never
// connected, and the agent must come back from both.
func TestEveryDatabasePathIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name, on string
		call     func(*statusConn) error
	}{
		{
			name: "heartbeat upsert", on: "status",
			call: func(c *statusConn) error { return c.report(context.Background(), "host-01") },
		},
		{
			name: "capability upsert", on: "capability",
			call: func(c *statusConn) error {
				return c.reportCapability(context.Background(), "host-01",
					hoststatus.ProbeResult{Kind: "openstack", Detected: true, Roles: []string{"compute"}})
			},
		},
		{
			name: "capability error record", on: "caperror",
			call: func(c *statusConn) error {
				return c.reportCapability(context.Background(), "host-01",
					hoststatus.ProbeResult{Kind: "openstack", Err: errors.New("probe timed out")})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &statusConn{
				attempt: 50 * time.Millisecond,
				open:    func(context.Context) (statusSink, error) { return &hangingSink{on: tc.on}, nil },
			}
			done := make(chan error, 1)
			go func() { done <- tc.call(c) }()

			select {
			case err := <-done:
				if err == nil {
					t.Errorf("a write that never returned was reported as success")
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("%s is still waiting; the deadline does not reach this path", tc.name)
			}
		})
	}
}

// A timed-out attempt must release the lock. Holding it would take the other
// loop down with it and turn one slow query into an agent that never reports
// again — the exact silent stop the deadline exists to prevent.
func TestATimedOutAttemptReleasesTheLock(t *testing.T) {
	sinks := []statusSink{&hangingSink{on: "status"}, &fakeStatusSink{}}
	var n int
	c := &statusConn{
		attempt: 50 * time.Millisecond,
		open: func(context.Context) (statusSink, error) {
			s := sinks[n]
			n++
			return s, nil
		},
	}

	if err := c.report(context.Background(), "host-01"); err == nil {
		t.Fatal("the hanging write was reported as success")
	}
	done := make(chan error, 1)
	go func() { done <- c.report(context.Background(), "host-01") }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the heartbeat after a timeout failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the next heartbeat never ran: the timed-out attempt still holds the lock")
	}
}
