package hoststatus

import (
	"context"
	"testing"
	"time"
)

// The deadline has to actually reach the probe, because that is the only thing
// bounding it. A runner that forgot to pass one would look identical from the
// outside — every probe here honours cancellation, so nothing would hang in a
// test — right up until a probe took a minute on a real host.
func TestEveryProbeIsHandedADeadline(t *testing.T) {
	var got context.Context
	p := &fakeProbe{collect: func(ctx context.Context) ProbeResult {
		got = ctx
		return ProbeResult{Detected: true}
	}}

	RunProbes(context.Background(), []Probe{p}, 50*time.Millisecond)

	if got == nil {
		t.Fatal("the probe was never called")
	}
	if _, ok := got.Deadline(); !ok {
		t.Error("the probe was handed a context with no deadline; nothing bounds it")
	}
}

// A probe that honours cancellation returns when the deadline expires, and the
// others still run. This is the contract Probe.Collect states; a probe that
// broke it would hold this loop, which is why it is written down.
func TestACancelledProbeReturnsAndTheRestStillRun(t *testing.T) {
	slow := &fakeProbe{kind: "slow", collect: func(ctx context.Context) ProbeResult {
		<-ctx.Done()
		return ProbeResult{Err: ctx.Err()}
	}}
	quick := &fakeProbe{kind: "quick", collect: func(context.Context) ProbeResult {
		return ProbeResult{Detected: true}
	}}

	done := make(chan []ProbeResult, 1)
	go func() { done <- RunProbes(context.Background(), []Probe{slow, quick}, 50*time.Millisecond) }()

	select {
	case out := <-done:
		if len(out) != 2 {
			t.Fatalf("got %d results, want one per probe", len(out))
		}
		if out[0].Err == nil {
			t.Error("the probe that ran out of time reported success")
		}
		if !out[1].Detected {
			t.Error("the probe after the slow one did not run")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunProbes never returned")
	}
}

type fakeProbe struct {
	kind    string
	collect func(context.Context) ProbeResult
}

func (f *fakeProbe) Kind() string {
	if f.kind == "" {
		return "fake"
	}
	return f.kind
}

func (f *fakeProbe) Collect(ctx context.Context) ProbeResult { return f.collect(ctx) }
