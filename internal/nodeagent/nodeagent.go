// Package nodeagent is the host-side daemon: it says this machine is alive, and
// separately says what platforms it is part of.
//
// It was a Cobra RunE and the functions under it. Flag parsing owned the two
// clocks, the startup offsets, the goroutine, the --once ordering, the shared
// database handle and its reconnect policy, and the deadline on every trip. All
// of that is invariant, several parts were learned from production, and none of
// it could be exercised without building a command tree.
//
// What is left in the CLI is flags and wiring. What is here is the lifecycle,
// and the ports it needs are small enough to fake: a sink to write to, a set of
// probes to run, somewhere to log.
//
// There is deliberately no scheduler abstraction. The two loops here differ in
// almost every way that matters — one is cheap and answers a question something
// waits on, the other is expensive and answers one nothing waits on — and the
// interesting parts are exactly the differences.
package nodeagent

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/ghdwlsgur/vctl/internal/hoststatus"
	"github.com/ghdwlsgur/vctl/internal/hoststatus/probes"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// Sink is the slice of the store the agent actually uses.
//
// Keeping it this narrow is what makes the reconnect behaviour testable without
// a database — and it is the whole surface a status credential should be able
// to reach.
type Sink interface {
	UpsertServerStatus(context.Context, store.ServerStatus) (bool, error)
	ReplaceCapabilities(ctx context.Context, hostname, kind string, caps []store.Capability) (bool, error)
	RecordCapabilityError(ctx context.Context, hostname, kind, message string) error
	Close()
}

// Agent is one host's reporting loop.
type Agent struct {
	// Hostname is the inventory name to report under, which is not always the
	// os hostname — one host in this fleet reports as k8s-all-01 while the
	// inventory calls it sre-srv-0023.
	Hostname string
	// Version goes in the heartbeat, so the fleet's agent versions are readable
	// centrally rather than by asking each host.
	Version string

	// Interval is the heartbeat's period; ProbeInterval the capability pass's.
	// Zero Interval falls back to defaultInterval. Zero ProbeInterval disables
	// capability probing entirely.
	Interval      time.Duration
	ProbeInterval time.Duration

	// Once runs one of each and returns. It is what the timer unit and the
	// smoke test use, and the ordering it implies is the reason the capability
	// pass is not always a goroutine — see Run.
	Once bool

	// OpenSink dials the database. Called again whenever a failure drops the
	// handle, so it must run the whole path — credential included.
	OpenSink func(context.Context) (Sink, error)

	// Probes is what one capability pass runs. Defaults to the platform probes.
	Probes func() []hoststatus.Probe

	// Warnf and Infof are where the few lines worth printing go. Default to
	// stderr.
	Warnf func(format string, args ...any)
	Infof func(format string, args ...any)

	// attempt bounds one trip to the database; zero means statusAttempt. Set in
	// tests, which cannot wait fifteen seconds to prove a hang is bounded.
	attempt time.Duration
}

const defaultInterval = 5 * time.Minute

// Run reports until the context is cancelled, or once and returns.
//
// The ordering here is the part with a history:
//
//   - The capability pass goes on its own goroutine only in daemon mode. Under
//     --once the process exits as soon as the heartbeat returns, and a probe
//     started in the background loses that race every time — the command
//     reported success having collected nothing. Running it inline is what
//     makes --once mean one of each.
//   - Under --once it runs *after* the heartbeat and regardless of whether the
//     heartbeat worked. The two answer different questions, and a host that
//     cannot report liveness can still say what it runs.
//   - Each loop waits out its own startup offset before its first run, and only
//     the first. See startPhase.
func (a *Agent) Run(ctx context.Context) error {
	if a.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	if a.OpenSink == nil {
		return fmt.Errorf("no way to reach the database")
	}
	c := &conn{open: a.OpenSink, attempt: a.attempt, log: a}
	defer c.close()

	if a.ProbeInterval > 0 && !a.Once {
		go a.capabilityLoop(ctx, c)
	}

	// Spread the fleet's first heartbeat. Every agent is installed and
	// restarted in the same pass, so without this they all reach Vault in the
	// same second. After this the interval is exact.
	//
	// Under --once there is no fleet and no next run, so a delay is nothing but
	// a slow command.
	if !a.Once && !waitFor(ctx, startPhase(heartbeatPhase, a.Hostname, "heartbeat")) {
		return nil
	}

	err := a.heartbeatLoop(ctx, c)
	if a.ProbeInterval > 0 && a.Once {
		a.capabilityPass(ctx, c)
	}
	return err
}

// heartbeatLoop runs the cheap half: one report now, then one per interval.
//
// A failure is logged and the loop continues. The agent's job is to keep saying
// the host is alive; giving up on the first failed attempt would mean an outage
// takes the reporting down with it and leaves nothing to notice the recovery.
func (a *Agent) heartbeatLoop(ctx context.Context, c *conn) error {
	report := func() error { return c.report(ctx, a.Hostname, a.Version) }
	if a.Once {
		return report()
	}
	interval := a.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	// The ping goes here, in the loop, and not in a goroutine of its own. A
	// separate pinger keeps answering systemd while this loop is wedged, which
	// is precisely the state worth catching — see watchdog.go.
	wd := newWatchdog()
	defer wd.close()
	warnTooSlow(wd, interval, a.warnf)

	if err := report(); err != nil {
		a.warnf("status report failed: %v", err)
	}
	wd.ping(a.warnf)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := report(); err != nil {
				a.warnf("status report failed: %v", err)
			}
			// After the report, success or not. A failed report is the loop
			// working; an absent ping is the loop not running.
			wd.ping(a.warnf)
		}
	}
}

// capabilityLoop runs the expensive half on its own, slower clock.
//
// The heartbeat answers "is this host alive" and has to stay cheap enough to
// run every five minutes forever. A pass asks systemd and several version
// commands, on the small fraction of hosts that have them, and the answer
// changes about as often as somebody upgrades. Running the two at one rate
// would either make the heartbeat slow or the capability stale.
func (a *Agent) capabilityLoop(ctx context.Context, c *conn) {
	// The expensive half, and nothing waits on it — so it takes the longer
	// offset, on its own hash, before it runs at all.
	if !waitFor(ctx, startPhase(capabilityPhase, a.Hostname, "capability")) {
		return
	}
	a.capabilityPass(ctx, c)
	t := time.NewTicker(a.ProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.capabilityPass(ctx, c)
		}
	}
}

// capabilityPass reports what platforms this host is part of.
//
// It never fails the agent. A probe error is recorded beside the last known
// facts and logged once; the heartbeat keeps running either way, because "we
// could not tell what this host runs" is not a reason to stop saying it is
// alive.
func (a *Agent) capabilityPass(ctx context.Context, c *conn) {
	for _, res := range hoststatus.RunProbes(ctx, a.probeSet(), probeTimeout) {
		if err := c.reportCapability(ctx, a.Hostname, res); err != nil {
			a.warnf("capability probe %s: %v", res.Kind, err)
		}
	}
}

func (a *Agent) probeSet() []hoststatus.Probe {
	if a.Probes != nil {
		return a.Probes()
	}
	return []hoststatus.Probe{probes.NewOpenStack()}
}

func (a *Agent) warnf(format string, args ...any) {
	if a.Warnf != nil {
		a.Warnf(format, args...)
		return
	}
	ui.Warnf(os.Stderr, format, args...)
}

func (a *Agent) infof(format string, args ...any) {
	if a.Infof != nil {
		a.Infof(format, args...)
		return
	}
	ui.Infof(os.Stderr, format, args...)
}

// probeTimeout bounds one probe. These shell out to commands this code does not
// own, on hosts that may be under load; a probe that never returns must not
// hold the agent's only goroutine for capabilities.
//
// 20s was too tight and the reason is the sandbox, not the host. The unit sets
// CPUQuota=2%, where a single fork costs ~0.4s — measured on a real controller,
// where `podman ps` alone took 3.9s and eight `systemctl show` calls took 3.1s.
// A full OpenStack controller could not finish inside 20s and recorded a
// timeout every hour. The probe runs once an hour on its own goroutine, so a
// wider budget costs nothing the heartbeat can feel.
const probeTimeout = 90 * time.Second

// How far into its window each loop's first run may be pushed.
//
// The whole fleet is installed in one pass and restarted in one pass, so every
// agent's first heartbeat lands in the same second: forty-odd AppRole logins,
// forty-odd dynamic database credentials, forty-odd pools. Nothing here is
// heavy enough for that to hurt yet, which is the reason to spread it while it
// is still cheap.
//
// The offset goes on the *first run only*; the interval afterwards is exact.
// Skewing the interval instead was the first attempt and it was the wrong
// shape: it left the startup pile-up completely untouched — both loops run once
// immediately, before any ticker exists — while making every host's heartbeat
// permanently something other than five minutes, so "the agent reports every
// five minutes" stopped being true of any host in the fleet.
//
// The heartbeat's window is short because a fresh deployment should confirm
// itself quickly; the capability probe's is longer because it is the expensive
// half — it forks systemctl, reads container sockets, and writes a row per role
// — and nothing waits on it.
const (
	heartbeatPhase  = 30 * time.Second
	capabilityPhase = 5 * time.Minute
)

// startPhase is how long a loop waits before its first run.
//
// Derived from the host's name rather than drawn at random, so a host keeps its
// slot across restarts instead of re-rolling into a fresh collision every time
// the unit bounces, and so "these two hosts always land together" is something
// that can be reproduced rather than waited for.
//
// The loop name is in the hash as well, so the two loops on one host get
// different offsets. With a single per-host fraction the capability probe
// landed on exactly the same tick as every twelfth heartbeat, on every host,
// forever — safe now that they share a lock, but the opposite of two clocks
// being kept apart.
//
// The hash is 64-bit because a Duration is a nanosecond count and the windows
// here are larger than a 32-bit hash can express. FNV-32 tops out at 4294967295,
// which as a Duration is 4.29s — smaller than either window, so `hash % window`
// did nothing at all and the hash fell through as the offset. Both windows
// collapsed to [0, 4.29s): the capability probe's was 70× narrower than written.
//
// Modulo bias with 64 bits is not worth correcting — a five-minute window
// divides 2^64 into some 60 million whole cycles.
func startPhase(window time.Duration, hostname, loop string) time.Duration {
	// No name to derive from, or no window to spread over: run now rather than
	// invent a schedule.
	if window <= 0 || hostname == "" {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(hostname))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(loop))
	return time.Duration(h.Sum64() % uint64(window))
}

// waitFor sleeps unless the context ends first, reporting whether the wait
// completed. Local rather than shared: what the agent does with a cancelled
// context here is part of its lifecycle, not a utility.
func waitFor(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// statusAttempt bounds one trip to Vault and Postgres.
//
// Without it the only deadline is the daemon's, which never fires. A TCP
// connection into a blackholed route does not fail, it hangs, and a heartbeat
// stuck there is a live process that has silently stopped reporting. systemd
// will not restart it because nothing crashed: the agent looks healthy and says
// nothing, which is the single failure this loop exists to make visible.
//
// 15s covers an AppRole login, a dynamic database credential, a TLS handshake
// and a ping with room to spare, and sits well inside the five-minute
// heartbeat, so a stuck attempt is abandoned rather than left to overlap the
// next one.
const statusAttempt = 15 * time.Second

// logger is what conn needs from the agent, so the connection code does not
// reach back into the whole struct.
type logger interface {
	warnf(format string, args ...any)
	infof(format string, args ...any)
}

// conn holds the agent's database handle across heartbeats and reopens it after
// a failure.
//
// The connection is deliberately not established before the loop starts.
// Opening it eagerly made a dependency that was down *at boot* fatal, while the
// very same dependency going down one heartbeat later was only a warning — the
// agent tolerated an outage it had already survived and died on one it had not.
// The boot case is the common one, because whatever takes Vault or Postgres out
// usually reboots hosts too.
type conn struct {
	// mu guards st and healthy, and is held across the database call rather
	// than around the handle.
	//
	// The heartbeat and the capability probe are separate goroutines on
	// different clocks, and once an hour their ticks land together. They share
	// one sink and a failure closes it, so a lock guarding only the pointer
	// would still let the heartbeat's close land while the capability write was
	// using what it closed. Without any lock, both could also open at the same
	// moment, leaving a pool and a Vault credential lease with no owner to close
	// them — a leak on the central side, once an hour, per host.
	//
	// Serialising costs a few milliseconds on a path that runs 288 times a day.
	mu   sync.Mutex
	open func(context.Context) (Sink, error)
	st   Sink

	attempt time.Duration
	log     logger

	// healthy tracks whether the last attempt succeeded, so success is logged
	// on the way back up rather than on every heartbeat. It starts false so the
	// first successful report still says so — a silent agent and a working one
	// would otherwise look identical at startup.
	healthy bool
}

// What a failure says about the connection, which is not the same for every
// caller. Named because `withSink(ctx, true, ...)` at a call site says nothing
// about which behaviour "true" is.
const (
	// dropOnFailure: this failure is evidence the handle is finished. Reopening
	// runs the full path again — AppRole login, then a fresh dynamic credential
	// — and a handle kept across such a failure can be one whose lease has
	// already lapsed, which no number of retries will fix.
	dropOnFailure = true
	// keepOnFailure: this failure is not evidence about the connection, so the
	// handle the heartbeat shares stays up. A capability write is the case: the
	// agent's job is to keep saying the host is alive, and "we could not tell
	// what it runs" is not a reason to make the heartbeat pay for a fresh Vault
	// login. If the database really is gone, the next heartbeat finds out and
	// drops it then.
	keepOnFailure = false
)

// withSink runs one operation against a live sink, opening one first if needed.
//
// Every path to the database goes through here, which is what makes the lock
// and the deadline hold for all of them rather than for whichever caller
// remembered.
func (c *conn) withSink(ctx context.Context, drop bool, fn func(context.Context, Sink) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	budget := c.attempt
	if budget <= 0 {
		budget = statusAttempt
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	if c.st == nil {
		st, err := c.open(ctx)
		if err != nil {
			return err
		}
		c.st = st
	}
	if err := fn(ctx, c.st); err != nil {
		if drop {
			c.closeLocked()
		}
		return err
	}
	return nil
}

// reportCapability writes one probe's findings.
//
// A probe that errored records the error against whatever is already stored and
// stops: overwriting the facts with an empty result would turn "the probe timed
// out" into "this host runs nothing", which reads as a decommission.
func (c *conn) reportCapability(ctx context.Context, hostname string, res hoststatus.ProbeResult) error {
	return c.withSink(ctx, keepOnFailure, func(ctx context.Context, st Sink) error {
		if res.Err != nil {
			return st.RecordCapabilityError(ctx, hostname, res.Kind, res.Err.Error())
		}
		// Nothing found is still an answer, and it needs a row so the listing
		// can tell "probed, absent" from "never probed". It is filed under the
		// role name "none".
		roles := res.Roles
		if len(roles) == 0 {
			roles = []string{"none"}
		}
		active := make(map[string]bool, len(res.ActiveRoles))
		for _, r := range res.ActiveRoles {
			active[r] = true
		}
		// Built first, written once. A role at a time was how this used to go,
		// and a failure halfway through left the host looking like it had
		// dropped the roles the loop had not reached yet.
		caps := make([]store.Capability, 0, len(roles))
		for _, role := range roles {
			cap := store.Capability{
				Hostname: hostname, Kind: res.Kind, Role: role,
				Detected: res.Detected, Active: active[role], Details: res.Details,
				Components: make(map[string]store.CapabilityComponent, len(res.Components)),
			}
			for name, comp := range res.Components {
				cap.Components[name] = store.CapabilityComponent{
					Version: comp.Version, Package: comp.Package,
					Active: comp.Active, Service: comp.Service,
				}
			}
			caps = append(caps, cap)
		}
		_, err := st.ReplaceCapabilities(ctx, hostname, res.Kind, caps)
		return err
	})
}

func (c *conn) report(ctx context.Context, hostname, version string) error {
	return c.withSink(ctx, dropOnFailure, func(ctx context.Context, st Sink) error {
		return reportStatus(ctx, st, hostname, version, &c.healthy, c.logger())
	})
}

// logger is the agent's, or stderr — which is where these lines went before
// there was anywhere to inject.
func (c *conn) logger() logger {
	if c.log != nil {
		return c.log
	}
	return stderrLog{}
}

type stderrLog struct{}

func (stderrLog) warnf(format string, args ...any) { ui.Warnf(os.Stderr, format, args...) }
func (stderrLog) infof(format string, args ...any) { ui.Infof(os.Stderr, format, args...) }

func (c *conn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *conn) closeLocked() {
	if c.st != nil {
		c.st.Close()
		c.st = nil
	}
	// Dropping the handle means the next success is a recovery, and recoveries
	// are exactly what this log is for.
	c.healthy = false
}

// reportStatus collects host status and upserts it for an already-registered
// host. A heartbeat for an unknown host is ignored (warned), not an error.
//
// Success is logged on transitions only: the first one after start, and the
// first after a failure. A daemon that logs every successful heartbeat writes
// 288 lines a day per host to say nothing happened, and the failures worth
// reading get buried in them.
// slowCollect is when gathering the status is worth complaining about.
//
// Collection reads a handful of small files under /proc and finishes in
// milliseconds. Seconds means one of those files is not small any more — the
// host that prompted this had a 2.8MB mount table.
//
// The number exists because the last time this went wrong there were no
// application logs at all — the agent burned a core for 57 days and the journal
// held nothing but systemd's own start lines, so the diagnosis went to strace.
// One line here would have said where to look.
const slowCollect = 2 * time.Second

func reportStatus(ctx context.Context, st Sink, hostname, version string, healthy *bool, log logger) error {
	// Collection only, and deliberately. The cycle also includes the write that
	// carries this number, so a total would have to describe itself — the row
	// would always say zero. Collection is the half that reads /proc, which is
	// the half that got expensive.
	started := time.Now()
	status := hoststatus.Collect(hostname, version)
	took := time.Since(started)
	ms := int(took.Milliseconds())
	status.CollectMs = &ms
	if took >= slowCollect {
		log.warnf("gathering status took %s (usually milliseconds); mount table has %s entries",
			took.Round(time.Millisecond), mountsFor(status))
	}

	ok, err := st.UpsertServerStatus(ctx, status)
	if err != nil {
		*healthy = false
		return err
	}
	if !ok {
		// Not a transition: an unregistered host is a standing misconfiguration
		// rather than an event, but it is also the reason no status will ever
		// appear, so it stays visible on every attempt.
		log.warnf("status ignored: %s is not registered in inventory", hostname)
		return nil
	}
	if !*healthy {
		log.infof("reporting status for %s", hostname)
		*healthy = true
	}
	return nil
}

// mountsFor renders the mount count for the slow-cycle warning, saying so when
// nothing measured it rather than printing a zero that reads like a fact.
func mountsFor(st store.ServerStatus) string {
	if st.MountCount == nil {
		return "an unknown number of"
	}
	return strconv.Itoa(*st.MountCount)
}
