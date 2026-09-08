package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

// wgTUICmd wires the flags for `vctl wg tui`; the work is runWGTUI.
func wgTUICmd(env cmdkit.Env) *cobra.Command {
	var opts wgTUIOptions
	cmd := &cobra.Command{
		Use:   "tui [host...]",
		Short: "Explore WireGuard tunnels in a live terminal map",
		Long: `Explore the synced topology with live SSH telemetry. Hosts restrict polling,
not the topology; other tunnels remain visible as unobserved. No topology writes.
Use up/down or j/k to select a site connection. Left/right selects a tunnel
within it. Enter folds the diagram; d opens technical details, PageUp/PageDown
scrolls details. Use / to filter, Esc to go back, and q to quit.
Non-interactive output prints the saved topology without opening SSH sessions.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWGTUI(cmd, env, args, opts)
		},
	}
	cmd.Flags().IntVar(&opts.interval, "interval", 2, "SSH poll interval in seconds")
	cmd.Flags().IntVar(&opts.timeout, "timeout", 10, "SSH timeout in seconds")
	return cmdkit.Gate(cmd, "wg")
}

// wgTUIOptions is the bound flag set of `wg tui`, in seconds.
type wgTUIOptions struct {
	interval, timeout int
}

// runWGTUI loads the saved topology, and — only on a terminal — starts the
// SSH poller and the screen. Without a terminal it prints the saved topology
// once and opens no SSH session, so a pipe gets the map and nothing else.
func runWGTUI(cmd *cobra.Command, env cmdkit.Env, args []string, opts wgTUIOptions) error {
	if opts.interval < 1 || opts.timeout < 1 {
		return fmt.Errorf("interval and timeout must be positive")
	}
	a, err := env.App()
	if err != nil {
		return err
	}
	st, err := a.OpenStore(cmd.Context(), app.PurposeInventoryRead)
	if err != nil {
		return err
	}
	defer st.Close()
	warn := func(f string, a ...any) { ui.Warnf(os.Stderr, f, a...) }
	snap, err := loadDashboardSnapshot(cmd.Context(), st, warn)
	if err != nil {
		return err
	}
	m := newWGTUI(snap.Topo, time.Duration(opts.interval)*time.Second)
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		m.height = 0
		fmt.Fprint(cmd.OutOrStdout(), m.View())
		return nil
	}
	targets, err := wgPollTargets(cmd.Context(), a, st, args, warn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	live := newLivePoller(cmdkit.NewConnector(a).Monitor(), targets, snap.EdgeFor, m.interval, time.Duration(opts.timeout)*time.Second)
	stop, _ := live.Start(ctx)
	defer stop()
	m.state = live.State()
	_, err = tea.NewProgram(m, tea.WithContext(ctx), tea.WithAltScreen(), tea.WithOutput(os.Stdout)).Run()
	return err
}

type wgTUITick time.Time

// wgTUI is the Bubble Tea model: the saved topology, the latest live snapshot
// (copied out of the poller's State once a second, so rendering never holds
// its lock), and the view state — cursor over site connections, tunnel within
// the connection, filter, fold and details toggles.
type wgTUI struct {
	topo                  wireguard.Topology
	nodes                 map[string]wireguard.Node
	state                 *wireguard.State
	live                  wireguard.LiveSnapshot
	interval              time.Duration
	now                   time.Time
	width, height, cursor int
	filter                string
	editing               bool
	panY, tunnel          int
	showDetails           bool
	collapsed             bool
}

// newWGTUI indexes the nodes and fixes the edge order, so the selection does
// not jump when rates change between ticks.
func newWGTUI(topo wireguard.Topology, interval time.Duration) wgTUI {
	m := wgTUI{topo: topo, nodes: map[string]wireguard.Node{}, interval: interval, now: time.Now(), width: 100, height: 24}
	for _, n := range topo.Nodes {
		m.nodes[n.ID] = n
	}
	// Keep the selection stable when rates change.
	m.topo.Edges = append([]wireguard.Edge(nil), topo.Edges...)
	sort.SliceStable(m.topo.Edges, func(i, j int) bool {
		a, b := m.topo.Edges[i], m.topo.Edges[j]
		return m.endpoint(a.Source)+a.ID < m.endpoint(b.Source)+b.ID
	})
	return m
}

func (m wgTUI) endpoint(id string) string {
	n, ok := m.nodes[id]
	if !ok {
		return id
	}
	site := n.DC
	if site == "" {
		site = "unknown site"
	}
	return "[" + site + "] " + n.Label
}

func (m wgTUI) edges() []wireguard.Edge {
	out := []wireguard.Edge{}
	for _, e := range m.topo.Edges {
		left, right := m.networkInfo(e.Source, e.B), m.networkInfo(e.Target, e.A)
		text := m.endpoint(e.Source) + " " + m.endpoint(e.Target) + " " + e.Iface + " " + e.Allowed + " " + left.name + " " + left.address + " " + right.name + " " + right.address
		if e.B != nil {
			text += " " + e.B.Iface + " " + e.B.Allowed
		}
		if strings.Contains(strings.ToLower(text), strings.ToLower(m.filter)) {
			out = append(out, e)
		}
	}
	return out
}

func (m wgTUI) Init() tea.Cmd { return m.tick() }
func (m wgTUI) tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return wgTUITick(t) })
}

// Update dispatches: a tick refreshes the live snapshot and re-arms; a key
// goes to the filter editor or the navigation handler; every path but the
// tick ends by clamping the selection to what the filter leaves visible.
func (m wgTUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	oldCursor := m.cursor
	switch msg := msg.(type) {
	case wgTUITick:
		m.now = time.Time(msg)
		if m.state != nil {
			m.live = m.state.Snapshot()
		}
		return m, m.tick()
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.editing {
			m.onFilterKey(msg)
		} else if m.onNavKey(msg.String()) {
			return m, tea.Quit
		}
	}
	m.clampSelection(oldCursor)
	return m, nil
}

// onFilterKey edits the search text. Any edit resets the selection to the
// top: the list under the cursor is about to change.
func (m *wgTUI) onFilterKey(msg tea.KeyMsg) {
	switch msg.String() {
	case "enter":
		m.editing = false
	case "esc":
		m.editing, m.filter = false, ""
	case "backspace":
		r := []rune(m.filter)
		if len(r) > 0 {
			m.filter = string(r[:len(r)-1])
		}
	default:
		if msg.Type == tea.KeyRunes {
			m.filter += string(msg.Runes)
		}
	}
	m.cursor = 0
	m.tunnel, m.panY = 0, 0
}

// onNavKey handles a key outside the filter editor and reports whether it
// asked to quit. Esc steps back one level — out of details first, then out
// of the filter — before it would ever mean quit, which it does not: q does.
func (m *wgTUI) onNavKey(key string) (quit bool) {
	switch key {
	case "q":
		return true
	case "esc":
		if m.showDetails {
			m.showDetails = false
			m.panY = 0
		} else {
			m.filter, m.cursor, m.tunnel = "", 0, 0
		}
	case "/":
		m.editing = true
	case "up", "k":
		m.cursor--
	case "down", "j":
		m.cursor++
	case "left", "h":
		m.tunnel--
		m.panY = 0
	case "right", "l":
		m.tunnel++
		m.panY = 0
	case "pgdown":
		m.panY += 6
	case "pgup":
		m.panY = max(0, m.panY-6)
	case "enter", "tab":
		m.collapsed = !m.collapsed
	case "d":
		m.showDetails = !m.showDetails
		m.panY = 0
	case "home":
		m.cursor = 0
	case "end":
		m.cursor = len(m.connections(m.edges())) - 1
	}
	return false
}

// clampSelection keeps the cursor and the tunnel index inside the filtered
// list, and resets the per-connection view state when the selection moved —
// a fold or an open details pane belongs to the connection it was opened on.
func (m *wgTUI) clampSelection(oldCursor int) {
	groups := m.connections(m.edges())
	m.cursor = max(0, min(m.cursor, len(groups)-1))
	if oldCursor != m.cursor {
		m.tunnel, m.panY = 0, 0
		m.collapsed, m.showDetails = false, false
	}
	if len(groups) > 0 {
		m.tunnel = max(0, min(m.tunnel, len(groups[m.cursor].edges)-1))
	} else {
		m.tunnel = 0
	}
}

// Each direction uses one observer, with a reversed far-end fallback. Never
// sum A.tx and B.rx: they describe the same traffic.
func (m wgTUI) observation(e wireguard.Edge, side *wireguard.EdgeSide) (wireguard.EdgeSideStat, string) {
	if side == nil {
		return wireguard.EdgeSideStat{}, "unobserved"
	}
	if m.live.Errors[side.Host] != "" {
		return wireguard.EdgeSideStat{}, "poll failed"
	}
	s, ok := m.live.Edges[e.ID].Sides[side.Host]
	if !ok {
		return s, "unobserved"
	}
	age := max(int64(0), m.now.Unix()-s.At)
	if age > max(int64(15), int64(m.interval.Seconds()*3)) {
		return s, "stale"
	}
	if s.HS < 0 {
		return s, "no handshake"
	}
	s.HS += age
	if s.HS > int64(wgHandshakeWindow.Seconds()) {
		return s, "idle"
	}
	return s, "recent HS"
}

func wgTUIColor(status string) lipgloss.Style {
	c := "245"
	switch status {
	case "recent HS":
		c = "42"
	case "idle", "stale", "no handshake", "one-sided":
		c = "214"
	case "poll failed", "conflict":
		c = "203"
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color(c))
}

func (m wgTUI) detail(e wireguard.Edge) []string {
	a, as := m.observation(e, e.A)
	b, bs := m.observation(e, e.B)
	rate := "waiting for observation"
	var forward, reverse float64
	hasRate := false
	if a.RateReady && (as == "recent HS" || as == "idle" || as == "no handshake") {
		forward, reverse, hasRate = a.TxPS, a.RxPS, true
		rate = "A → B  " + humanRate(a.TxPS) + "    B → A  " + humanRate(a.RxPS) + "  (A counters)"
	} else if b.RateReady && (bs == "recent HS" || bs == "idle" || bs == "no handshake") {
		forward, reverse, hasRate = b.RxPS, b.TxPS, true
		rate = "A → B  " + humanRate(b.RxPS) + "    B → A  " + humanRate(b.TxPS) + "  (B counters)"
	}
	out := []string{ui.Title("SELECTED TUNNEL"), "A  " + m.endpoint(e.Source), "B  " + m.endpoint(e.Target), rate}
	if hasRate {
		peak := max(forward, reverse)
		bar := func(value float64, color string) string {
			n := 0
			if peak > 0 {
				n = int(12 * value / peak)
			}
			return lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Render(strings.Repeat("█", n) + strings.Repeat("░", 12-n))
		}
		out = append(out, "A → B "+bar(forward, "39")+"  "+humanRate(forward), "B → A "+bar(reverse, "177")+"  "+humanRate(reverse), ui.Muted("Bars share a relative rate scale."))
	}
	for i, side := range []*wireguard.EdgeSide{e.A, e.B} {
		label := []string{"A", "B"}[i]
		s, status := m.observation(e, side)
		line := label + "  " + status
		if side != nil {
			line += " · " + side.Host + "/" + side.Iface
		}
		if status == "recent HS" || status == "idle" {
			line += fmt.Sprintf(" · HS %ds ago", s.HS)
		}
		out = append(out, wgTUIColor(status).Render(line))
		if side != nil {
			out = append(out, label+" AllowedIPs: "+side.Allowed)
			if err := m.live.Errors[side.Host]; err != "" {
				out = append(out, ui.Warn(err))
			}
		}
	}
	if e.Conflict {
		out = append(out, ui.Warn("! Conflicting endpoint identity"))
	}
	return out
}
