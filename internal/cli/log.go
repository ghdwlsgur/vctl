package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// logCmd renders one host's node-agent healthcheck as a small dashboard: the
// heartbeat's freshness and everything the last report carried — load, memory,
// disk, uptime, the agent's own vitals. It reads the same server_status row
// the fleet views aggregate, so this is `vctl status` zoomed to one machine.
//
// server_status keeps the latest report, not a series, so the dashboard shows
// current state stamped with the agent's clock rather than a history.
func logCmd(env CommandEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "log [host]",
		Short: "Show one host's node-agent healthcheck as a dashboard",
		Long: `log shows the node-agent's latest healthcheck for one host: heartbeat
freshness, host vitals (load, memory, disk, uptime), and the agent's own
self-observability numbers.

  vctl log sre-srv-0049`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.newApp()
			if err != nil {
				return err
			}
			inv, err := a.OpenInventory(ctx)
			if err != nil {
				return err
			}
			defer inv.Close()

			sv, err := pick(ctx, inv, args)
			if err != nil {
				return err
			}
			rows, err := withLiveStatus(ctx, inv, []store.Server{*sv})
			if err != nil {
				return err
			}
			renderHostLog(&rows[0], inv.Cached())
			return nil
		},
	}
}

// renderHostLog draws the one-host dashboard.
func renderHostLog(ws *store.ServerWithStatus, cached bool) {
	w := os.Stdout
	ui.Section(w, ws.Hostname+" — node-agent healthcheck")

	if ws.Status == nil {
		ui.KVs(w, []ui.KV{
			{Key: "Agent", Value: "not installed — no report has ever arrived", State: ui.StateWarn},
			{Key: "Install", Value: "vctl inject " + ws.Hostname + " && vctl install " + ws.Hostname, State: ui.StatePlain},
		})
		return
	}
	st := ws.Status

	rows := []ui.KV{agentRow(ws, cached)}
	if st.OS != "" || st.Kernel != "" {
		rows = append(rows, ui.KV{Key: "Host", Value: strings.TrimSpace(st.OS + " · " + st.Kernel), State: ui.StatePlain})
	}
	if st.UptimeSeconds > 0 {
		rows = append(rows, ui.KV{Key: "Uptime", Value: strutil.CompactDuration(time.Duration(st.UptimeSeconds) * time.Second), State: ui.StatePlain})
	}
	if st.Load1 != nil {
		rows = append(rows, ui.KV{Key: "Load (1m)", Value: fmt.Sprintf("%.2f", *st.Load1), State: ui.StatePlain})
	}
	rows = append(rows, gaugeRow("Memory", st.MemoryUsedPct))
	rows = append(rows, gaugeRow("Disk /", st.DiskRootUsedPct))
	if len(st.ObservedIPs) > 0 {
		rows = append(rows, ui.KV{Key: "Observed IPs", Value: strings.Join(st.ObservedIPs, ", "), State: ui.StatePlain})
	}
	rows = append(rows, agentVitalsRow(st)...)
	ui.KVs(w, rows)
}

// agentRow is the headline: is the agent alive, and how stale is the picture
// below it. Everything else on the dashboard is only as current as this row.
// The verdict itself comes from liveStatusText — the shared liveness decision
// every status-aware view uses — so the up/stale threshold lives in one place.
func agentRow(ws *store.ServerWithStatus, cached bool) ui.KV {
	st := ws.Status
	age := time.Since(st.LastSeenAt).Round(time.Second)
	ver := ""
	if st.AgentVersion != "" {
		ver = " · " + st.AgentVersion
	}
	switch {
	case cached:
		return ui.KV{Key: "Agent", Value: fmt.Sprintf("snapshot data%s — liveness unknown offline", ver), State: ui.StateWarn}
	case liveStatusText(*ws) == "up":
		return ui.KV{Key: "Agent", Value: fmt.Sprintf("up — reported %s ago%s", strutil.CompactDuration(age), ver), State: ui.StateOK}
	default:
		return ui.KV{Key: "Agent", Value: fmt.Sprintf("stale — last report %s ago%s (data below is that old)", strutil.CompactDuration(age), ver), State: ui.StateWarn}
	}
}

// agentVitalsRow reports the agent's self-observability numbers when present.
// Pointers because absent and zero are different answers — see store.ServerStatus.
func agentVitalsRow(st *store.ServerStatus) []ui.KV {
	if st.MountCount == nil && st.CollectMs == nil {
		return nil
	}
	parts := []string{}
	if st.MountCount != nil {
		parts = append(parts, fmt.Sprintf("%d mounts scanned", *st.MountCount))
	}
	if st.CollectMs != nil {
		parts = append(parts, fmt.Sprintf("collect took %dms", *st.CollectMs))
	}
	return []ui.KV{{Key: "Agent vitals", Value: strings.Join(parts, " · "), State: ui.StatePlain}}
}

// gaugeRow renders a percentage as a ten-cell meter with the usual traffic
// lights (90 critical, 75 warn). A nil value renders as "not reported" rather
// than 0% — an agent that predates the metric has measured nothing.
func gaugeRow(label string, pct *float64) ui.KV {
	if pct == nil {
		return ui.KV{Key: label, Value: "not reported", State: ui.StatePlain}
	}
	p := *pct
	state := ui.StateOK
	switch {
	case p >= 90:
		state = ui.StateFail
	case p >= 75:
		state = ui.StateWarn
	}
	return ui.KV{Key: label, Value: fmt.Sprintf("%s %5.1f%%", ui.Meter(p, 10), p), State: state}
}
