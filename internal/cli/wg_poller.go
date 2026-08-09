package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

// livePoller is the moving half of the dashboard: an SSH session to every
// gateway, `wg show all dump` on a fixed interval, and the tunnel state that
// falls out of it.
//
// It is separate from the snapshot because it is the expensive half and the one
// with teeth. The drawing is a database read that costs nothing to repeat; this
// holds connections open to production gateways for as long as the page is up,
// which is why `make wg-down` exists and why stopping it has to be one call
// rather than a cancel buried in a request handler.
type livePoller struct {
	targets  []monTarget
	mon      *access.Monitor
	state    *wireguard.State
	edgeFor  map[wireguard.TunnelKey]string
	interval time.Duration
	timeout  time.Duration
}

// wgPollTargets resolves the gateways to poll and the route to each one.
//
// A gateway that cannot be resolved is warned about and dropped rather than
// failing the command: eleven reachable gateways and one that moved is a
// dashboard worth opening, and the page draws the missing one as unobserved. All
// of them failing is different — there is then nothing live to show, and
// starting a server that animates nothing is worse than saying so.
func wgPollTargets(ctx context.Context, a *app.App, st *store.Store, args []string, warn func(format string, args ...any)) ([]monTarget, error) {
	hosts, err := wgMonitorHosts(ctx, st, args, false)
	if err != nil {
		return nil, err
	}
	targets := make([]monTarget, 0, len(hosts))
	for i := range hosts {
		tgt, err := access.BuildTarget(ctx, st, &hosts[i], a.Cfg.SSHDirectFirst)
		if err != nil {
			warn("%s: %v", hosts[i].Hostname, err)
			continue
		}
		targets = append(targets, monTarget{name: hosts[i].Hostname, tgt: tgt})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no reachable gateways to poll")
	}
	return targets, nil
}

func newLivePoller(mon *access.Monitor, targets []monTarget, edgeFor map[wireguard.TunnelKey]string, interval, timeout time.Duration) *livePoller {
	return &livePoller{
		targets:  targets,
		mon:      mon,
		state:    wireguard.NewState(),
		edgeFor:  edgeFor,
		interval: interval,
		timeout:  timeout,
	}
}

// State is what the page reads. It is live from the first poll and safe to read
// before any of them have landed — an unpolled gateway reports as unobserved,
// which is a state the page draws rather than an absence it has to guess at.
func (p *livePoller) State() *wireguard.State { return p.state }

// Gateways is how many machines this is holding sessions to, for the line the
// command prints when it starts.
func (p *livePoller) Gateways() int { return len(p.targets) }

// Start launches one goroutine per gateway and returns a stop function.
//
// Stop is what the caller defers. Cancelling the context the goroutines watch is
// the only way they end, and returning the canceller rather than storing it
// keeps "who is allowed to stop this" answerable by reading the call site.
func (p *livePoller) Start(ctx context.Context) (stop func(), done <-chan struct{}) {
	pollCtx, cancel := context.WithCancel(ctx)
	for _, t := range p.targets {
		go p.run(pollCtx, t)
	}
	return cancel, pollCtx.Done()
}

// run is one gateway's loop. A failed poll is recorded rather than retried
// differently or logged and forgotten: "this gateway stopped answering ninety
// seconds ago" is a thing the page draws, and it can only draw it if the failure
// reaches the state.
func (p *livePoller) run(ctx context.Context, t monTarget) {
	for {
		// Polling telemetry, not access: Monitor records the first poll per
		// gateway and every change of outcome after that, instead of a row
		// every 2s. See access.Monitor.
		res, err := p.mon.Poll(ctx, access.Request{Target: t.tgt, HostKey: access.HostKeyAcceptNew}, wireguard.DumpCmd, p.timeout)
		if err != nil {
			p.state.Fail(t.name, err)
		} else {
			_, ps := wireguard.ParseDump(res.Stdout)
			p.state.Record(t.name, samples(ps), time.Now(), p.edgeFor)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(p.interval):
		}
	}
}
