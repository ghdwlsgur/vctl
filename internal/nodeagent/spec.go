package nodeagent

import (
	"context"
	"errors"
	"time"

	"github.com/ghdwlsgur/vctl/internal/hwspec"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// The spec pass is the fourth loop: the machine's hardware, for the asset
// sheet. Hardware changes when somebody opens the chassis, so once a day is
// already generous; the interval is fixed for the same reason the MOTD's is.
//
// It reads the SMBIOS table and sysfs, which is cheap even at CPUQuota=2% —
// no forks — but it is still the least urgent thing the agent does, so it
// takes the widest start offset.
const (
	specInterval = 24 * time.Hour
	specPhase    = 30 * time.Minute
)

func (a *Agent) specLoop(ctx context.Context, c *conn) {
	if !waitFor(ctx, startPhase(specPhase, a.Hostname, "spec")) {
		return
	}
	a.specPass(ctx, c)
	t := time.NewTicker(specInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.specPass(ctx, c)
		}
	}
}

// specPass collects and writes the hardware spec. A guest is skipped quietly:
// the sheet is for bare metal, and a VM saying so every day is not news.
func (a *Agent) specPass(ctx context.Context, c *conn) {
	collect := a.CollectSpec
	if collect == nil {
		collect = hwspec.NewCollector().Collect
	}
	sp, err := collect()
	if errors.Is(err, hwspec.ErrVirtual) {
		return
	}
	if err != nil {
		a.warnf("spec: %v", err)
		return
	}
	err = c.withSink(ctx, keepOnFailure, func(ctx context.Context, st Sink) error {
		_, err := st.UpsertServerSpec(ctx, store.ServerSpec{
			Hostname: a.Hostname, Source: store.SpecSourceAgent, Spec: sp, Collector: a.Version,
		})
		return err
	})
	if err != nil {
		a.warnf("spec: writing: %v", err)
	}
}
