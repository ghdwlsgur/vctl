package wireguard

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// A gateway that answers, one that has no WireGuard, and one that cannot be
// reached — the three outcomes every flow was counting for itself.
func collectorOver(out map[string]string, fail map[string]error, save func(string)) *Collector {
	return &Collector{
		Run: func(_ context.Context, h Host) (string, error) {
			if err := fail[h.Name]; err != nil {
				return "", err
			}
			return out[h.Name], nil
		},
		Save: func(_ context.Context, host string, _ []store.WGInterface, _ []store.WGPeer, _ []store.WGPeerStatus) error {
			if save != nil {
				save(host)
			}
			return nil
		},
	}
}

func hosts(names ...string) []Host {
	out := make([]Host, 0, len(names))
	for _, n := range names {
		out = append(out, Host{Name: n})
	}
	return out
}

// The aggregation is the half that drifted: two implementations of "what
// counted" reported different numbers for the same fleet.
func TestEveryHostLandsInExactlyOneBucket(t *testing.T) {
	c := collectorOver(
		map[string]string{"gw-1": sampleCollect(), "gw-2": "@@ADDR@@"},
		map[string]error{"gw-3": errors.New("connection refused")},
		nil,
	)
	rep := c.Collect(context.Background(), hosts("gw-1", "gw-2", "gw-3"))

	if rep.Probed != 3 {
		t.Errorf("probed = %d, want the three it was given", rep.Probed)
	}
	if rep.WithWG+rep.Skipped+rep.Failed != rep.Probed {
		t.Errorf("counts do not add up: with=%d skipped=%d failed=%d probed=%d",
			rep.WithWG, rep.Skipped, rep.Failed, rep.Probed)
	}
	if rep.WithWG != 1 || rep.Skipped != 1 || rep.Failed != 1 {
		t.Errorf("buckets = %+v", rep)
	}
	if rep.Interfaces == 0 || rep.Peers == 0 {
		t.Errorf("nothing was counted from the gateway that answered: %+v", rep)
	}
}

// A host that answers with nothing configured must not have its rows replaced
// by emptiness — that would erase a gateway the first time its wg was down.
func TestAHostWithNoWireGuardIsNotWritten(t *testing.T) {
	var saved []string
	c := collectorOver(map[string]string{"gw-2": "@@ADDR@@"}, nil, func(h string) {
		saved = append(saved, h)
	})
	rep := c.Collect(context.Background(), hosts("gw-2"))

	if len(saved) != 0 {
		t.Errorf("wrote %v for a host with no WireGuard", saved)
	}
	if rep.Skipped != 1 || rep.Failed != 0 {
		t.Errorf("a host with nothing configured counted as %+v, want skipped", rep)
	}
}

// A dry run has no sink at all, so it exercises the real path minus the write.
func TestADryRunCollectsAndParsesWithoutWriting(t *testing.T) {
	c := collectorOver(map[string]string{"gw-1": sampleCollect()}, nil, nil)
	c.Save = nil
	rep := c.Collect(context.Background(), hosts("gw-1"))

	if rep.WithWG != 1 || rep.Interfaces == 0 {
		t.Errorf("a dry run collected nothing: %+v", rep)
	}
	if rep.Failed != 0 {
		t.Errorf("a dry run reported %d failures", rep.Failed)
	}
}

// One unreachable gateway is not a reason to abandon the rest, and the report
// is where that is said rather than an error that stops the sweep.
func TestOneFailureDoesNotStopTheSweep(t *testing.T) {
	c := collectorOver(
		map[string]string{"gw-1": sampleCollect(), "gw-3": sampleCollect()},
		map[string]error{"gw-2": errors.New("timeout")},
		nil,
	)
	c.Concurrency = 3
	rep := c.Collect(context.Background(), hosts("gw-1", "gw-2", "gw-3"))

	if rep.WithWG != 2 {
		t.Errorf("with wireguard = %d, want the two that answered", rep.WithWG)
	}
	if rep.Failed != 1 {
		t.Errorf("failed = %d, want the one that did not", rep.Failed)
	}
	var reported bool
	for _, r := range rep.Results {
		if r.Host == "gw-2" && r.Err != nil {
			reported = true
		}
	}
	if !reported {
		t.Error("the failure is not in the report, so nothing can name the host that failed")
	}
}

// Concurrency is a bound, not a suggestion: a sweep across the fleet must not
// open more sessions at once than it was told to.
func TestConcurrencyIsBounded(t *testing.T) {
	var mu sync.Mutex
	var inFlight, peak int
	c := &Collector{
		Concurrency: 2,
		Run: func(_ context.Context, h Host) (string, error) {
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()
			defer func() { mu.Lock(); inFlight--; mu.Unlock() }()
			return sampleCollect(), nil
		},
	}
	c.Collect(context.Background(), hosts("a", "b", "c", "d", "e", "f"))

	if peak > 2 {
		t.Errorf("peak concurrency %d exceeded the bound of 2", peak)
	}
}

// Zero means one at a time, which is what a pre-sync inside an interactive
// command wants — not "unbounded", which is what a zero-length channel would
// have meant.
func TestZeroConcurrencyRunsOneAtATime(t *testing.T) {
	var mu sync.Mutex
	var inFlight, peak int
	c := &Collector{
		Run: func(_ context.Context, h Host) (string, error) {
			mu.Lock()
			inFlight++
			if inFlight > peak {
				peak = inFlight
			}
			mu.Unlock()
			defer func() { mu.Lock(); inFlight--; mu.Unlock() }()
			return "@@ADDR@@", nil
		},
	}
	c.Collect(context.Background(), hosts("a", "b", "c"))

	if peak != 1 {
		t.Errorf("peak concurrency %d with no bound set, want serial", peak)
	}
}
