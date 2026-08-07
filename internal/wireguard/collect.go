package wireguard

import (
	"context"
	"fmt"
	"sync"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// Collecting WireGuard state was assembled separately by every flow that needed
// it. `wg sync` ran the command, parsed it, skipped hosts without WireGuard,
// wrote the rows and counted the outcomes; `wg monitor --sync` did the same
// thing again, sequentially, with a different idea of what counted as a
// failure. Two copies of "what a collection is" drift, and the half that drifts
// is usually the aggregation — so one flow reports six gateways collected and
// the other reports five from the same fleet.
//
// This owns it once: run, parse, drop what has no WireGuard, persist, and hand
// back what happened. The flows keep what is theirs — which hosts, how to reach
// them, and how to show the result.

// CollectCmd is what runs on a gateway: the WireGuard dump and the interface
// addresses, in one round trip.
//
// Public data only — ParseCollect drops the private and preshared keys before
// anything is stored. `sudo -n` first because a gateway usually needs root to
// read the dump, falling back to an unprivileged attempt so a host configured
// the other way still answers.
const CollectCmd = `{ sudo -n wg show all dump 2>/dev/null || wg show all dump 2>/dev/null; }; echo '@@ADDR@@'; { ip -o -4 addr show 2>/dev/null; ip -o -6 addr show 2>/dev/null; }`

// DumpCmd is the lighter poll command for monitoring — the runtime dump alone,
// with no address lookup, because a poll is asking what changed rather than
// what exists.
const DumpCmd = `sudo -n wg show all dump 2>/dev/null || wg show all dump 2>/dev/null`

// Host is one gateway to collect from. Target is whatever the caller's transport
// needs to reach it; this package neither builds nor inspects it.
type Host struct {
	Name   string
	Target any
}

// Sink is where collected state goes. Narrow on purpose: a collection writes
// one host's rows and nothing else.
type Sink interface {
	WGReplaceHost(ctx context.Context, host string, ifaces []store.WGInterface, peers []store.WGPeer, statuses []store.WGPeerStatus) error
}

// Collector runs one collection over a set of gateways.
type Collector struct {
	// Run executes CollectCmd against one host and returns its stdout.
	Run func(ctx context.Context, h Host) (string, error)

	// Save persists one host's rows. Nil is a dry run: everything is collected
	// and parsed, nothing is written — which is what makes --dry-run exercise
	// the real path rather than a description of it.
	Save func(ctx context.Context, host string, ifaces []store.WGInterface, peers []store.WGPeer, statuses []store.WGPeerStatus) error

	// Concurrency bounds how many gateways are probed at once. Zero means one
	// at a time, which is what a pre-sync inside an interactive command wants.
	Concurrency int

	// OnHost, when set, is called as each host finishes, for a flow that prints
	// progress rather than a summary.
	OnHost func(HostResult)
}

// HostResult is what happened to one gateway.
type HostResult struct {
	Host string
	// Interfaces and Peers are what was collected, zero when the host has no
	// WireGuard or the attempt failed.
	Interfaces int
	Peers      int
	// NoWireGuard is a host that answered with nothing configured. Not a
	// failure: most of the inventory is not a gateway.
	NoWireGuard bool
	Err         error
}

// Report is the whole collection.
type Report struct {
	Probed     int
	WithWG     int
	Interfaces int
	Peers      int
	Skipped    int
	Failed     int
	Results    []HostResult
}

// Collect probes every host and returns what happened.
//
// It never returns an error: one gateway being unreachable is not a reason to
// abandon the rest, and the report says which ones failed. A caller that wants
// to fail on that reads Report.Failed.
func (c *Collector) Collect(ctx context.Context, hosts []Host) Report {
	rep := Report{Probed: len(hosts), Results: make([]HostResult, 0, len(hosts))}
	limit := c.Concurrency
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, h := range hosts {
		h := h
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res := c.collectOne(ctx, h)
			mu.Lock()
			switch {
			case res.Err != nil:
				rep.Failed++
			case res.NoWireGuard:
				rep.Skipped++
			default:
				rep.WithWG++
				rep.Interfaces += res.Interfaces
				rep.Peers += res.Peers
			}
			rep.Results = append(rep.Results, res)
			onHost := c.OnHost
			mu.Unlock()
			if onHost != nil {
				onHost(res)
			}
		}()
	}
	wg.Wait()
	return rep
}

func (c *Collector) collectOne(ctx context.Context, h Host) HostResult {
	out, err := c.Run(ctx, h)
	if err != nil {
		return HostResult{Host: h.Name, Err: err}
	}
	ifaces, peers, statuses := ParseCollect(h.Name, out)
	if len(ifaces) == 0 {
		// Answered, with nothing configured. Writing that would replace a
		// gateway's rows with emptiness the first time its wg was down.
		return HostResult{Host: h.Name, NoWireGuard: true}
	}
	if c.Save != nil {
		if err := c.Save(ctx, h.Name, ifaces, peers, statuses); err != nil {
			return HostResult{Host: h.Name, Err: fmt.Errorf("store: %w", err)}
		}
	}
	return HostResult{Host: h.Name, Interfaces: len(ifaces), Peers: len(peers)}
}
