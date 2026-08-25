package nodeagent

import (
	"context"
	"time"

	"github.com/ghdwlsgur/vctl/internal/motd"
)

// The MOTD pass is the third loop, and the slowest. It reads the inventory's
// view of the host's farm and keeps /etc/motd matching it. Like the capability
// pass, nothing waits on it; unlike the capability pass it only reads, so a
// failure is a warning and the shared handle stays up.
//
// The interval is fixed rather than a flag. The data changes when the
// reconciler runs, which is hourly at the fastest, so a knob here could only
// be turned to a value that reads stale data more often.
const motdInterval = 30 * time.Minute

func (a *Agent) motdLoop(ctx context.Context, c *conn) {
	if !waitFor(ctx, startPhase(capabilityPhase, a.Hostname, "motd")) {
		return
	}
	a.motdPass(ctx, c)
	t := time.NewTicker(motdInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.motdPass(ctx, c)
		}
	}
}

// motdPass renders the banner and writes it only when it differs.
//
// A host in no farm renders "" and nothing is written or removed: this code
// only ever claims the file on machines whose topology it can describe, so
// enabling the flag fleet-wide cannot blank a banner somebody else owns.
func (a *Agent) motdPass(ctx context.Context, c *conn) {
	if a.MOTDPath == "" {
		return
	}
	var content string
	err := c.withSink(ctx, keepOnFailure, func(ctx context.Context, st Sink) error {
		farms, err := st.FarmTopologies(ctx, a.Hostname)
		if err != nil {
			return err
		}
		content = motd.Render(motd.Banner{
			Header:    a.MOTDHeader,
			ManagedBy: a.MOTDManagedBy,
			Self:      a.Hostname,
		}, farms)
		return nil
	})
	if err != nil {
		a.warnf("motd: reading farm topology: %v", err)
		return
	}
	if content == "" {
		return
	}
	changed, err := motd.Sync(a.MOTDPath, content)
	if err != nil {
		a.warnf("motd: writing %s: %v", a.MOTDPath, err)
		return
	}
	if changed {
		a.infof("motd: %s updated from inventory topology", a.MOTDPath)
	}
}
