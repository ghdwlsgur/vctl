package cli

import (
	"bufio"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// selectServer shows a scrollable, type-to-filter picker (radio-style rows in a
// fixed-height viewport with "↑/↓ N more" overflow counters). Falls back to a
// numbered prompt when stdin isn't a TTY (pipes, CI).
// cached marks the candidates as coming from the local snapshot, which
// suppresses the liveness column — see liveStatus.
func selectServer(cands []store.ServerWithStatus, title string, cached bool) (*store.ServerWithStatus, error) {
	if len(cands) == 0 {
		return nil, fmt.Errorf("no servers to choose from")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return numberPick(cands, title, cached)
	}

	m := newPickerModel(cands, title, cached)
	// Render to stderr so a piped stdout (e.g. `vctl ssh ... | tee`) stays clean,
	// and read keys from the real terminal.
	prog := tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithInput(os.Stdin))
	res, err := prog.Run()
	if err != nil {
		return nil, fmt.Errorf("selection failed: %w", err)
	}
	pm := res.(pickerModel)
	if pm.chosen < 0 {
		return nil, fmt.Errorf("selection cancelled")
	}
	return &cands[pm.chosen], nil
}

const pickerViewport = 10 // visible rows in the scrolling area

var (
	pickCursorStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	pickSelectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	pickDimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

type pickerModel struct {
	title    string
	cands    []store.ServerWithStatus
	filtered []int    // indices into cands matching the query+DC, in order
	dcs      []string // DC tabs; index 0 is "" = all DCs, rest sorted
	dcIdx    int      // selected DC tab (←/→)
	query    string
	cursor   int // index into filtered
	offset   int // first visible index into filtered
	height   int // viewport rows
	width    int
	chosen   int  // index into cands, -1 if cancelled
	cached   bool // candidates came from the local snapshot

	// addrWidth is measured rather than fixed. A bare IPv4 fits in 16, but a
	// non-default port adds up to 6 more, and a fixed 16 would push the DC column
	// right on exactly the rows that already stand out. Measuring keeps the
	// column tight when every host is on 22 — which is most of them.
	addrWidth int
}

func newPickerModel(cands []store.ServerWithStatus, title string, cached bool) pickerModel {
	m := pickerModel{
		title:     title,
		cands:     cands,
		dcs:       distinctDCs(cands),
		height:    pickerViewport,
		width:     100,
		chosen:    -1,
		cached:    cached,
		addrWidth: addrColumnWidth(cands),
	}
	if w, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil && w > 0 {
		m.width = w
	}
	m.refilter()
	return m
}

// distinctDCs returns the sorted distinct DC labels of cands, with "" (all DCs)
// at index 0 so ←/→ can cycle through "all" then each DC.
func distinctDCs(cands []store.ServerWithStatus) []string {
	seen := map[string]bool{}
	var dcs []string
	for _, c := range cands {
		if c.DC != "" && !seen[c.DC] {
			seen[c.DC] = true
			dcs = append(dcs, c.DC)
		}
	}
	slices.Sort(dcs)
	return append([]string{""}, dcs...)
}

func (m pickerModel) Init() tea.Cmd { return nil }

func (m *pickerModel) refilter() {
	q := strings.ToLower(strings.TrimSpace(m.query))
	dc := m.dcs[m.dcIdx] // "" = all DCs
	m.filtered = m.filtered[:0]
	for i, c := range m.cands {
		if dc != "" && c.DC != dc {
			continue
		}
		if q == "" || matchServer(c, q) {
			m.filtered = append(m.filtered, i)
		}
	}
	m.cursor = 0
	m.offset = 0
}

func matchServer(c store.ServerWithStatus, q string) bool {
	return strings.Contains(strings.ToLower(c.Hostname), q) ||
		strings.Contains(strings.ToLower(c.IP), q) ||
		strings.Contains(strings.ToLower(c.DC), q) ||
		strings.Contains(strings.ToLower(c.User), q) ||
		// The port is on screen, so it has to be typeable. Searching "10022" to
		// find the hosts behind that port is the reason to show it at all.
		strconv.Itoa(c.Port) == q
}

// addrColumnMin is the width the address column had before ports were shown.
// Keeping it as a floor means a fleet where every host is on 22 renders exactly
// as it did — the column only grows for the lists that need it.
const addrColumnMin = 16

// addrColumnWidth measures the address column across every candidate, so the
// column is only as wide as the widest port actually present.
func addrColumnWidth(cands []store.ServerWithStatus) int {
	w := addrColumnMin
	for _, c := range cands {
		if n := lipgloss.Width(addrCell(c.IP, c.Port)); n > w {
			w = n
		}
	}
	return w
}

func (m *pickerModel) clampScroll() {
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = len(m.filtered) - 1
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+m.height {
		m.offset = m.cursor - m.height + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func (m pickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if msg.Width > 0 {
			m.width = msg.Width
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			m.chosen = -1
			return m, tea.Quit
		case tea.KeyEnter:
			if len(m.filtered) > 0 {
				m.chosen = m.filtered[m.cursor]
			}
			return m, tea.Quit
		case tea.KeyUp, tea.KeyCtrlP:
			m.cursor--
			m.clampScroll()
			return m, nil
		case tea.KeyDown, tea.KeyCtrlN:
			m.cursor++
			m.clampScroll()
			return m, nil
		case tea.KeyLeft:
			if len(m.dcs) > 1 {
				m.dcIdx = (m.dcIdx - 1 + len(m.dcs)) % len(m.dcs)
				m.refilter()
			}
			return m, nil
		case tea.KeyRight:
			if len(m.dcs) > 1 {
				m.dcIdx = (m.dcIdx + 1) % len(m.dcs)
				m.refilter()
			}
			return m, nil
		case tea.KeyBackspace:
			if m.query != "" {
				r := []rune(m.query)
				m.query = string(r[:len(r)-1])
				m.refilter()
			}
			return m, nil
		case tea.KeyRunes, tea.KeySpace:
			m.query += string(msg.Runes)
			m.refilter()
			return m, nil
		}
	}
	return m, nil
}

func (m pickerModel) View() string {
	var b strings.Builder

	// Title with a trailing rule that fills the line, like the mockup header.
	title := ui.Title(m.title)
	ruleLen := max(m.width-lipgloss.Width(title)-1, 0)
	b.WriteString(title)
	if ruleLen > 0 {
		b.WriteString(" ")
		b.WriteString(pickDimStyle.Render(strings.Repeat("─", ruleLen)))
	}
	b.WriteString("\n")

	b.WriteString(pickDimStyle.Render("Search: "))
	b.WriteString(m.query)
	b.WriteString("\n")
	help := "↑↓ move, type to filter, enter confirm, esc cancel"
	if len(m.dcs) > 2 {
		help = "↑↓ move, ←→ DC, type to filter, enter confirm, esc cancel"
	}
	b.WriteString(pickDimStyle.Render(help))
	b.WriteString("\n")
	if len(m.dcs) > 2 {
		label := m.dcs[m.dcIdx]
		if label == "" {
			label = "all DCs"
		}
		b.WriteString(pickDimStyle.Render("DC ‹ "))
		b.WriteString(pickCursorStyle.Render(label))
		b.WriteString(pickDimStyle.Render(fmt.Sprintf(" ›  %d/%d", m.dcIdx+1, len(m.dcs))))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if len(m.filtered) == 0 {
		b.WriteString(pickDimStyle.Render("  (no matches)"))
		b.WriteString("\n")
		return b.String()
	}

	end := min(m.offset+m.height, len(m.filtered))
	for i := m.offset; i < end; i++ {
		b.WriteString(m.renderRow(i))
		b.WriteString("\n")
	}

	// Overflow counters: how many rows lie above/below the fixed viewport.
	if m.offset > 0 {
		b.WriteString(pickDimStyle.Render(fmt.Sprintf("↑ %d more", m.offset)))
		b.WriteString("\n")
	}
	if below := len(m.filtered) - end; below > 0 {
		b.WriteString(pickDimStyle.Render(fmt.Sprintf("↓ %d more", below)))
		b.WriteString("\n")
	}
	return b.String()
}

func (m pickerModel) renderRow(i int) string {
	c := m.cands[m.filtered[i]]
	// Reserve room for the "› ● " gutter plus the trailing status column.
	nameWidth := 40
	if w := m.width - 60; w > 20 && w < nameWidth {
		nameWidth = w
	}
	label := fmt.Sprintf("%-*s %-*s %-12s %s",
		nameWidth, ui.Truncate(c.Hostname, nameWidth),
		m.addrWidth, addrCell(c.IP, c.Port), c.DC, liveStatus(c, m.cached))

	if i == m.cursor {
		return pickCursorStyle.Render("› ●") + " " + pickSelectedStyle.Render(label)
	}
	return pickDimStyle.Render("  ○ ") + label
}

// numberPick is the non-TTY fallback (pipes/CI): a plain numbered prompt.
func numberPick(cands []store.ServerWithStatus, title string, cached bool) (*store.ServerWithStatus, error) {
	ui.Section(os.Stderr, title)
	w := addrColumnWidth(cands)
	for i, c := range cands {
		fmt.Fprintf(os.Stderr, "  %2d  %-28s %-*s %-12s %s\n",
			i+1, c.Hostname, w, addrCell(c.IP, c.Port), c.DC, liveStatus(c, cached))
	}
	fmt.Fprint(os.Stderr, ui.Muted("number: "))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(cands) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &cands[n-1], nil
}
