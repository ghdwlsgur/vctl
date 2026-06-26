package cli

import (
	"bufio"
	"fmt"
	"os"
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
func selectServer(cands []store.ServerWithStatus, title string) (*store.ServerWithStatus, error) {
	if len(cands) == 0 {
		return nil, fmt.Errorf("no servers to choose from")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return numberPick(cands, title)
	}

	m := newPickerModel(cands, title)
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
	filtered []int // indices into cands matching the query, in order
	query    string
	cursor   int // index into filtered
	offset   int // first visible index into filtered
	height   int // viewport rows
	width    int
	chosen   int // index into cands, -1 if cancelled
}

func newPickerModel(cands []store.ServerWithStatus, title string) pickerModel {
	m := pickerModel{
		title:  title,
		cands:  cands,
		height: pickerViewport,
		width:  100,
		chosen: -1,
	}
	if w, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil && w > 0 {
		m.width = w
	}
	m.refilter()
	return m
}

func (m pickerModel) Init() tea.Cmd { return nil }

func (m *pickerModel) refilter() {
	q := strings.ToLower(strings.TrimSpace(m.query))
	m.filtered = m.filtered[:0]
	for i, c := range m.cands {
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
		strings.Contains(strings.ToLower(c.User), q)
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
	b.WriteString(pickDimStyle.Render("↑↓ move, type to filter, enter confirm, esc cancel"))
	b.WriteString("\n\n")

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
	label := fmt.Sprintf("%-*s %-16s %-12s %s",
		nameWidth, ui.Truncate(c.Hostname, nameWidth), c.IP, c.DC, liveStatus(c))

	if i == m.cursor {
		return pickCursorStyle.Render("› ●") + " " + pickSelectedStyle.Render(label)
	}
	return pickDimStyle.Render("  ○ ") + label
}

// numberPick is the non-TTY fallback (pipes/CI): a plain numbered prompt.
func numberPick(cands []store.ServerWithStatus, title string) (*store.ServerWithStatus, error) {
	ui.Section(os.Stderr, title)
	for i, c := range cands {
		fmt.Fprintf(os.Stderr, "  %2d  %-28s %-16s %-12s %s\n", i+1, c.Hostname, c.IP, c.DC, liveStatus(c))
	}
	fmt.Fprint(os.Stderr, ui.Muted("number: "))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(cands) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &cands[n-1], nil
}
