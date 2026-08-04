package cli

import (
	"context"
	"fmt"
	"os"
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

			conn := &statusConn{open: func() (statusSink, error) {
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
	run()
	if once {
		return
	}
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

type statusConn struct {
	open func() (statusSink, error)
	st   statusSink

	// healthy tracks whether the last attempt succeeded, so success is logged
	// on the way back up rather than on every heartbeat. It starts false so the
	// first successful report still says so — a silent agent and a working one
	// would otherwise look identical at startup.
	healthy bool
}

// reportCapability writes one probe's findings.
//
// A probe that errored records the error against whatever is already stored and
// stops: overwriting the facts with an empty result would turn "the probe timed
// out" into "this host runs nothing", which reads as a decommission.
func (c *statusConn) reportCapability(ctx context.Context, hostname string, res hoststatus.ProbeResult) error {
	if c.st == nil {
		st, err := c.open()
		if err != nil {
			return err
		}
		c.st = st
	}
	if res.Err != nil {
		return c.st.RecordCapabilityError(ctx, hostname, res.Kind, res.Err.Error())
	}
	// Nothing found is still an answer, and it needs a row so the listing can
	// tell "probed, absent" from "never probed". It is filed under the role
	// name "none".
	roles := res.Roles
	if len(roles) == 0 {
		roles = []string{"none"}
	}
	for _, role := range roles {
		cap := store.Capability{
			Hostname: hostname, Kind: res.Kind, Role: role,
			Detected: res.Detected, Details: res.Details,
			Components: make(map[string]store.CapabilityComponent, len(res.Components)),
			ObservedAt: res.ObservedAt,
		}
		for name, comp := range res.Components {
			cap.Components[name] = store.CapabilityComponent{
				Version: comp.Version, Package: comp.Package,
				Active: comp.Active, Service: comp.Service,
			}
		}
		if _, err := c.st.UpsertCapability(ctx, cap); err != nil {
			return err
		}
	}
	return nil
}

func (c *statusConn) report(ctx context.Context, hostname string) error {
	if c.st == nil {
		st, err := c.open()
		if err != nil {
			return err
		}
		c.st = st
	}
	if err := reportStatus(ctx, c.st, hostname, &c.healthy); err != nil {
		c.close()
		return err
	}
	return nil
}

func (c *statusConn) close() {
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
