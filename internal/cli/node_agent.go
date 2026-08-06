package cli

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/hoststatus"
	"github.com/ghdwlsgur/vctl/internal/hoststatus/probes"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func nodeAgentCmd() *cobra.Command {
	var (
		hostname      string
		interval      time.Duration
		probeInterval time.Duration
		once          bool
	)
	cmd := &cobra.Command{
		Use:   "node-agent",
		Short: "Report lightweight host runtime status",
		Long: `node-agent reports observed host state to server_status.

It never creates inventory. The host must already exist in the servers table;
otherwise the heartbeat is ignored. Use AppRole credentials and a narrow
database role for low-risk, low-resource status reporting.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}

			if hostname == "" {
				hostname, _ = os.Hostname()
			}
			if hostname == "" {
				return fmt.Errorf("hostname is required")
			}

			conn := &statusConn{open: func(ctx context.Context) (statusSink, error) {
				return a.OpenStore(ctx, app.PurposeStatus)
			}}
			defer conn.close()

			// Capability probes run on their own, slower clock.
			//
			// The heartbeat answers "is this host alive" and has to stay cheap
			// enough to run every five minutes forever. A probe asks systemd and
			// several version commands, on the small fraction of hosts that have
			// them, and the answer changes about as often as somebody upgrades —
			// which is to say rarely. Running the two at one rate would either
			// make the heartbeat slow or the capability stale.
			//
			// Only the long-running agent puts them on a goroutine. Under --once
			// the process exits as soon as the single heartbeat returns, and a
			// probe started in the background loses the race every time — the
			// command reported success having collected nothing. Running it
			// inline is what makes --once mean one of each.
			if probeInterval > 0 && !once {
				go runCapabilityProbes(ctx, conn, hostname, probeInterval, false)
			}

			// Spread the fleet's first heartbeat. Every agent is installed and
			// restarted in the same pass, so without this they all reach Vault
			// in the same second. After this the interval is exact.
			//
			// Under --once there is no fleet and no next run, so a delay is
			// nothing but a slow command — and the capability probe does not
			// reach here at all in that mode; it runs inline after the
			// heartbeat, below. In daemon mode its goroutine started above and
			// waits out its own, longer offset.
			if !once && !waitForContext(ctx, startPhase(heartbeatPhase, hostname, "heartbeat")) {
				return nil
			}

			report := func() error { return conn.report(ctx, hostname) }
			err = runPeriodic(ctx, once, false, interval, 5*time.Minute, report, func(err error) {
				ui.Warnf(os.Stderr, "status report failed: %v", err)
			})
			if probeInterval > 0 && once {
				// After the heartbeat, and regardless of whether it worked. The
				// two answer different questions and a host that cannot report
				// liveness can still say what it runs.
				runCapabilityProbes(ctx, conn, hostname, probeInterval, true)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "inventory hostname to report; defaults to os hostname")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "heartbeat interval")
	cmd.Flags().DurationVar(&probeInterval, "probe-interval", time.Hour,
		"how often to run platform capability probes (OpenStack, ...); 0 disables them")
	cmd.Flags().BoolVar(&once, "once", false, "report once and exit")
	return cmd
}

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
// Not jitterWatchDelay, which draws fresh each call. That one spreads retries
// after an outage, where a new draw every attempt is right. This is a standing
// position in a schedule, so it has to be stable.
// The hash is 64-bit because a Duration is a nanosecond count and the windows
// here are larger than a 32-bit hash can express. FNV-32 tops out at 4294967295,
// which as a Duration is 4.29s — smaller than either window, so `hash % window`
// did nothing at all and the hash fell through as the offset. Both windows
// collapsed to [0, 4.29s): the capability probe's was 70× narrower than written.
//
// Modulo bias with 64 bits is not worth correcting — a five-minute window
// divides 2^64 into some 60 million whole cycles.
func startPhase(window time.Duration, hostname, loop string) time.Duration {
	if window <= 0 || hostname == "" {
		return 0
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(hostname))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(loop))
	return time.Duration(h.Sum64() % uint64(window))
}

// capabilityProbes is what this agent knows how to look for. Adding a platform
// is adding an entry here; nothing else in the agent changes.
func capabilityProbes() []hoststatus.Probe {
	return []hoststatus.Probe{probes.NewOpenStack()}
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

// runCapabilityProbes reports what platforms this host is part of.
//
// It never fails the agent. A probe error is recorded beside the last known
// facts and logged once; the heartbeat keeps running either way, because "we
// could not tell what this host runs" is not a reason to stop saying it is
// alive.
func runCapabilityProbes(ctx context.Context, conn *statusConn, hostname string, every time.Duration, once bool) {
	run := func() {
		for _, res := range hoststatus.RunProbes(ctx, capabilityProbes(), probeTimeout) {
			if err := conn.reportCapability(ctx, hostname, res); err != nil {
				ui.Warnf(os.Stderr, "capability probe %s: %v", res.Kind, err)
			}
		}
	}
	if once {
		// Inline and immediate: --once has to mean one of each, and the caller
		// exits the moment this returns.
		run()
		return
	}
	// The expensive half of the agent, and nothing waits on it — so it takes
	// the longer offset, on its own hash, before it runs at all.
	if !waitForContext(ctx, startPhase(capabilityPhase, hostname, "capability")) {
		return
	}
	run()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// statusConn holds the agent's database handle across heartbeats and reopens it
// after a failure.
//
// The connection is deliberately not established before the loop starts. Opening
// it eagerly made a dependency that was down *at boot* fatal, while the very same
// dependency going down one heartbeat later was only a warning — the agent
// tolerated an outage it had already survived and died on one it had not. The
// boot case is the common one, because whatever takes Vault or Postgres out
// usually reboots hosts too.
//
// Dropping the handle on error matters as much as retrying. Reopening runs the
// full path again: AppRole login, then a fresh dynamic database credential. A
// handle kept across a failure can be one whose lease has already lapsed, and no
// number of retries on it will ever succeed.
// statusSink is the slice of *store.Store the agent actually uses. Keeping it
// this narrow is what makes the reconnect behavior testable without a database.
type statusSink interface {
	UpsertServerStatus(context.Context, store.ServerStatus) (bool, error)
	UpsertCapability(context.Context, store.Capability) (bool, error)
	RecordCapabilityError(ctx context.Context, hostname, kind, message string) error
	Close()
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

type statusConn struct {
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
	open func(context.Context) (statusSink, error)
	st   statusSink

	// attempt bounds one trip; zero means statusAttempt. Set in tests, which
	// cannot wait fifteen seconds to prove a hang is bounded.
	attempt time.Duration

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
func (c *statusConn) withSink(ctx context.Context, drop bool, fn func(context.Context, statusSink) error) error {
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
func (c *statusConn) reportCapability(ctx context.Context, hostname string, res hoststatus.ProbeResult) error {
	return c.withSink(ctx, keepOnFailure, func(ctx context.Context, st statusSink) error {
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
		for _, role := range roles {
			cap := store.Capability{
				Hostname: hostname, Kind: res.Kind, Role: role,
				Detected: res.Detected, Active: active[role], Details: res.Details,
				Components: make(map[string]store.CapabilityComponent, len(res.Components)),
				ObservedAt: res.ObservedAt,
			}
			for name, comp := range res.Components {
				cap.Components[name] = store.CapabilityComponent{
					Version: comp.Version, Package: comp.Package,
					Active: comp.Active, Service: comp.Service,
				}
			}
			if _, err := st.UpsertCapability(ctx, cap); err != nil {
				return err
			}
		}
		return nil
	})
}

func (c *statusConn) report(ctx context.Context, hostname string) error {
	return c.withSink(ctx, dropOnFailure, func(ctx context.Context, st statusSink) error {
		return reportStatus(ctx, st, hostname, &c.healthy)
	})
}

func (c *statusConn) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}

func (c *statusConn) closeLocked() {
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
// reading get buried in them. The same reasoning already applies to wg
// monitoring, which audits transitions instead of every poll.
func reportStatus(ctx context.Context, st statusSink, hostname string, healthy *bool) error {
	status := hoststatus.Collect(hostname, Version)
	ok, err := st.UpsertServerStatus(ctx, status)
	if err != nil {
		*healthy = false
		return err
	}
	if !ok {
		// Not a transition: an unregistered host is a standing misconfiguration
		// rather than an event, but it is also the reason no status will ever
		// appear, so it stays visible on every attempt.
		ui.Warnf(os.Stderr, "status ignored: %s is not registered in inventory", hostname)
		return nil
	}
	if !*healthy {
		ui.Infof(os.Stderr, "reporting status for %s", hostname)
		*healthy = true
	}
	return nil
}
