package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// wgDumpCmd is the lighter poll command for monitoring — just the runtime dump
// (public data), no `ip addr`. sudo first, plain fallback for root logins.
const wgDumpCmd = `sudo -n wg show all dump 2>/dev/null || wg show all dump 2>/dev/null`

// monTarget is a resolved gateway to poll.
type monTarget struct {
	name string
	tgt  *sshc.Target
}

func wgMonitorCmd() *cobra.Command {
	var (
		intervalSec, timeoutSec int
		syncFirst, all          bool
	)
	cmd := &cobra.Command{
		Use:   "monitor [host...]",
		Short: "Live WireGuard traffic monitor (per-tunnel throughput, handshakes)",
		Long: `monitor polls the given gateways (or all previously synced ones) with
'wg show' on an interval and shows live per-peer throughput (rx/tx deltas) and
handshake freshness — a top(1) for WireGuard tunnels. Reads live over SSH; it
does not write to the DB. Non-interactive stdout prints a single snapshot.

--sync runs one collection into the DB before monitoring (so the very first run
has data). Because that writes, it additionally requires the 'wg-sync' grant.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
			if err != nil {
				return err
			}
			defer st.Close()

			hosts, err := wgMonitorHosts(ctx, st, args, all)
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				return fmt.Errorf("no gateways to monitor: pass host names, --all, or run 'vctl wg sync' first")
			}
			targets := make([]monTarget, 0, len(hosts))
			for i := range hosts {
				tgt, err := access.BuildTarget(ctx, st, &hosts[i], a.Cfg.SSHDirectFirst)
				if err != nil {
					ui.Warnf(os.Stderr, "%s: %v", hosts[i].Hostname, err)
					continue
				}
				targets = append(targets, monTarget{name: hosts[i].Hostname, tgt: tgt})
			}
			if len(targets) == 0 {
				return fmt.Errorf("no reachable gateways")
			}

			conn := newConnector(a)
			interval := time.Duration(intervalSec) * time.Second
			timeout := time.Duration(timeoutSec) * time.Second

			if syncFirst {
				if err := wgSyncBeforeMonitor(ctx, a, conn, targets, timeout); err != nil {
					return err
				}
			}

			if !term.IsTerminal(int(os.Stdout.Fd())) {
				return wgMonitorSnapshot(ctx, conn, targets, timeout)
			}
			// The TUI polls on a timer, so it audits transitions rather than
			// every tick. The one-shot paths above keep auditing each run.
			m := newMonitorModel(ctx, conn.Monitor(), targets, interval, timeout)
			_, err = tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithInput(os.Stdin)).Run()
			return err
		},
	}
	cmd.Flags().IntVar(&intervalSec, "interval", 2, "poll interval (seconds)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 10, "per-poll SSH timeout (seconds)")
	cmd.Flags().BoolVar(&syncFirst, "sync", false, "collect into the DB once before monitoring (needs the wg-sync grant)")
	cmd.Flags().BoolVar(&all, "all", false, "with no host args, target every inventory host")
	return gate(cmd, "wg", classRead)
}

// wgSyncBeforeMonitor runs one collection of the monitor targets into the DB,
// used by `wg monitor --sync`. Monitoring is read-only, so this write path is
// gated at runtime by the same 'wg-sync' permission the sync command carries —
// keeping the two-layer RBAC model intact even though the command is classRead.
func wgSyncBeforeMonitor(ctx context.Context, a *app.App, conn *access.Connector, targets []monTarget, timeout time.Duration) error {
	if err := newAuthorizer(a).Check(ctx, authz.Command{Name: "wg-sync", Class: classMutate}); err != nil {
		return err
	}
	st, err := a.OpenStore(ctx, app.PurposeInventoryWrite)
	if err != nil {
		return err
	}
	defer st.Close()
	var withWG int
	for _, t := range targets {
		res, err := conn.Execute(ctx, access.Request{Target: t.tgt, HostKey: access.HostKeyAcceptNew}, wgCollectCmd, timeout)
		if err != nil {
			ui.Warnf(os.Stderr, "%s: %v", t.name, err)
			continue
		}
		ifaces, peers, statuses := parseWGCollect(t.name, res.Stdout)
		if len(ifaces) == 0 {
			continue
		}
		if err := st.WGReplaceHost(ctx, t.name, ifaces, peers, statuses); err != nil {
			ui.Warnf(os.Stderr, "%s: store: %v", t.name, err)
			continue
		}
		withWG++
	}
	ui.Successf(os.Stderr, "pre-sync: %d/%d gateways collected", withWG, len(targets))
	return nil
}

// wgMonitorHosts picks gateways: explicit args, else the hosts already present
// in wg_interfaces (previously synced gateways).
func wgMonitorHosts(ctx context.Context, st *store.Store, args []string, all bool) ([]store.Server, error) {
	if len(args) > 0 {
		out := make([]store.Server, 0, len(args))
		for _, q := range args {
			sv, err := access.ResolveServer(ctx, st, q)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", q, err)
			}
			out = append(out, *sv)
		}
		return out, nil
	}
	ifaces, err := st.WGInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []store.Server
	for _, i := range ifaces {
		if seen[i.Host] {
			continue
		}
		seen[i.Host] = true
		sv, err := access.ResolveServer(ctx, st, i.Host)
		if err != nil {
			continue
		}
		out = append(out, *sv)
	}
	// Fresh DB (no synced gateways yet): --all falls back to the whole inventory
	// so `wg monitor --sync --all` works as a zero-setup first run.
	if len(out) == 0 && all {
		return st.List(ctx, "")
	}
	return out, nil
}

// --- polling ---

type tunnelKey struct{ host, iface, peer string }

type wgSample struct {
	rx, tx int64
	hs     *time.Time
	at     time.Time
}

type pollResultMsg struct {
	host  string
	peers []wgParsedPeer
	err   error
	at    time.Time
}

type tickMsg time.Time

// pollHost returns a tea.Cmd that SSHes into one gateway, runs wg show and
// returns the parsed peers. It never blocks the UI: bubbletea runs it async.
func pollHost(ctx context.Context, mon *access.Monitor, t monTarget, timeout time.Duration) tea.Cmd {
	return func() tea.Msg {
		res, err := mon.Poll(ctx, access.Request{Target: t.tgt, HostKey: access.HostKeyAcceptNew}, wgDumpCmd, timeout)
		if err != nil {
			return pollResultMsg{host: t.name, err: err, at: time.Now()}
		}
		_, peers := parseWGDump(res.Stdout)
		return pollResultMsg{host: t.name, peers: peers, at: time.Now()}
	}
}

// --- rate math (pure, testable) ---

// computeRate returns bytes/sec between two samples, guarding against counter
// resets (restart) and zero/negative time deltas.
func computeRate(prev, cur wgSample) (rxps, txps float64) {
	dt := cur.at.Sub(prev.at).Seconds()
	if dt <= 0 {
		return 0, 0
	}
	drx, dtx := cur.rx-prev.rx, cur.tx-prev.tx
	if drx < 0 {
		drx = 0 // counter reset (iface/peer re-created)
	}
	if dtx < 0 {
		dtx = 0
	}
	return float64(drx) / dt, float64(dtx) / dt
}

// humanBytes formats a byte count with binary units.
func humanBytes(n int64) string {
	f := float64(n)
	const k = 1024.0
	switch {
	case f >= k*k*k:
		return fmt.Sprintf("%.1fG", f/(k*k*k))
	case f >= k*k:
		return fmt.Sprintf("%.1fM", f/(k*k))
	case f >= k:
		return fmt.Sprintf("%.1fK", f/k)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

func humanRate(bps float64) string {
	if bps < 1 {
		return ui.Muted("·")
	}
	return humanBytes(int64(bps)) + "/s"
}

// --- bubbletea model ---

type monitorModel struct {
	ctx      context.Context
	mon      *access.Monitor
	targets  []monTarget
	interval time.Duration
	timeout  time.Duration

	prev   map[tunnelKey]wgSample
	cur    map[tunnelKey]wgSample
	rates  map[tunnelKey][2]float64 // rxps, txps
	errs   map[string]string
	paused bool
	w, h   int
}

func newMonitorModel(ctx context.Context, mon *access.Monitor, targets []monTarget, interval, timeout time.Duration) monitorModel {
	return monitorModel{
		ctx: ctx, mon: mon, targets: targets, interval: interval, timeout: timeout,
		prev: map[tunnelKey]wgSample{}, cur: map[tunnelKey]wgSample{},
		rates: map[tunnelKey][2]float64{}, errs: map[string]string{},
	}
}

func (m monitorModel) Init() tea.Cmd { return tea.Batch(m.pollAll(), m.tick()) }

func (m monitorModel) pollAll() tea.Cmd {
	cmds := make([]tea.Cmd, 0, len(m.targets))
	for _, t := range m.targets {
		cmds = append(cmds, pollHost(m.ctx, m.mon, t, m.timeout))
	}
	return tea.Batch(cmds...)
}

func (m monitorModel) tick() tea.Cmd {
	return tea.Tick(m.interval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m monitorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "p":
			m.paused = !m.paused
		}
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tickMsg:
		if m.paused {
			return m, m.tick()
		}
		return m, tea.Batch(m.pollAll(), m.tick())
	case pollResultMsg:
		if msg.err != nil {
			m.errs[msg.host] = msg.err.Error()
			return m, nil
		}
		delete(m.errs, msg.host)
		for _, p := range msg.peers {
			k := tunnelKey{msg.host, p.Iface, p.PubKey}
			var hs *time.Time
			if p.Handshake > 0 {
				t := time.Unix(p.Handshake, 0)
				hs = &t
			}
			s := wgSample{rx: p.Rx, tx: p.Tx, hs: hs, at: msg.at}
			if old, ok := m.cur[k]; ok {
				m.prev[k] = old
				rx, tx := computeRate(old, s)
				m.rates[k] = [2]float64{rx, tx}
			}
			m.cur[k] = s
		}
	}
	return m, nil
}

func (m monitorModel) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).
		Render("WireGuard monitor")
	status := ui.Muted(fmt.Sprintf("· %d gateways · every %s · q quit · p %s",
		len(m.targets), m.interval, map[bool]string{true: "resume", false: "pause"}[m.paused]))
	head := title + " " + status + "\n\n"

	type row struct {
		key  tunnelKey
		s    wgSample
		rxps float64
		txps float64
	}
	rows := make([]row, 0, len(m.cur))
	for k, s := range m.cur {
		r := row{key: k, s: s}
		if rt, ok := m.rates[k]; ok {
			r.rxps, r.txps = rt[0], rt[1]
		}
		rows = append(rows, r)
	}
	// Sort by current total throughput desc, then host/iface for stability.
	sort.Slice(rows, func(i, j int) bool {
		ti, tj := rows[i].rxps+rows[i].txps, rows[j].rxps+rows[j].txps
		if ti != tj {
			return ti > tj
		}
		if rows[i].key.host != rows[j].key.host {
			return rows[i].key.host < rows[j].key.host
		}
		return rows[i].key.iface < rows[j].key.iface
	})

	hdr := ui.Muted(fmt.Sprintf("  %-22s %-6s %-10s %10s %10s   %s",
		"gateway", "iface", "peer", "↓ rx/s", "↑ tx/s", "handshake"))
	var sb []string
	sb = append(sb, head+hdr)
	for _, r := range rows {
		line := fmt.Sprintf("  %-22s %-6s %-10s %10s %10s   %s",
			ui.Truncate(r.key.host, 22), r.key.iface, shortKey(r.key.peer),
			humanRate(r.rxps), humanRate(r.txps), wgHandshakeCell(r.s.hs))
		sb = append(sb, line)
	}
	out := ""
	for _, l := range sb {
		out += l + "\n"
	}
	if len(m.errs) > 0 {
		out += "\n"
		for host, e := range m.errs {
			out += ui.Warn("  ! "+host+": ") + ui.Muted(ui.Truncate(e, 60)) + "\n"
		}
	}
	return out
}

// wgMonitorSnapshot polls once and prints a table — the non-interactive path.
func wgMonitorSnapshot(ctx context.Context, conn *access.Connector, targets []monTarget, timeout time.Duration) error {
	var mu sync.Mutex
	var wg sync.WaitGroup
	rows := [][]string{}
	for _, t := range targets {
		wg.Add(1)
		go func(t monTarget) {
			defer wg.Done()
			res, err := conn.Execute(ctx, access.Request{Target: t.tgt, HostKey: access.HostKeyAcceptNew}, wgDumpCmd, timeout)
			if err != nil {
				return
			}
			_, peers := parseWGDump(res.Stdout)
			mu.Lock()
			defer mu.Unlock()
			for _, p := range peers {
				var hs *time.Time
				if p.Handshake > 0 {
					tt := time.Unix(p.Handshake, 0)
					hs = &tt
				}
				rows = append(rows, []string{t.name, p.Iface, shortKey(p.PubKey),
					humanBytes(p.Rx), humanBytes(p.Tx), wgHandshakeCell(hs)})
			}
		}(t)
	}
	wg.Wait()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i][0] != rows[j][0] {
			return rows[i][0] < rows[j][0]
		}
		return rows[i][1] < rows[j][1]
	})
	ui.Section(os.Stdout, "wg monitor (snapshot)")
	return ui.Table(os.Stdout, []string{"gateway", "iface", "peer", "rx", "tx", "handshake"}, rows)
}
