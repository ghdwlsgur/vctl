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

	"github.com/ghdwlsgur/vctl/internal/ui"
)

// Generic string-list picker (single- and multi-select), mirroring the server
// picker in picker.go: scrollable, type-to-filter viewport with a non-TTY
// numbered fallback. Used by `vctl rbac assign` to pick a group then users.
//
// Keys: ↑/↓ move, type to filter, enter confirm, esc cancel. In multi mode,
// space toggles the row under the cursor (so type-to-filter uses letters only).

// pickOne returns the chosen value, or "" if cancelled.
func pickOne(items []string, title string) (string, error) {
	idx, _, err := runListPicker(items, nil, title, false)
	if err != nil {
		return "", err
	}
	if len(idx) == 0 {
		return "", fmt.Errorf("selection cancelled")
	}
	return items[idx[0]], nil
}

// listGroups is an optional filter dimension for the picker: the group each
// candidate belongs to, plus the name of the dimension for the tab row. It is a
// struct rather than a bare slice so the picker never has to assume what the
// grouping means — the host picker groups by datacenter, and a later caller
// that groups by something else should not have to render "DC".
type listGroups struct {
	name string   // shown in the tab row, e.g. "DC"
	of   []string // group of each candidate, positionally
}

// pickIndex is single-select for callers that need the row's position rather
// than its text. g may be nil, which means no tabs.
func pickIndex(items []string, g *listGroups, title string) (int, error) {
	idxs, cancelled, err := runListPicker(items, g, title, false)
	if err != nil {
		return -1, err
	}
	if cancelled || len(idxs) == 0 {
		return -1, fmt.Errorf("selection cancelled")
	}
	return idxs[0], nil
}

// pickMany returns the chosen values (possibly empty if nothing toggled).
func pickMany(items []string, title string) ([]string, error) {
	idxs, cancelled, err := runListPicker(items, nil, title, true)
	if err != nil {
		return nil, err
	}
	if cancelled {
		return nil, fmt.Errorf("selection cancelled")
	}
	out := make([]string, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, items[i])
	}
	return out, nil
}

func runListPicker(items []string, g *listGroups, title string, multi bool) (chosen []int, cancelled bool, err error) {
	if len(items) == 0 {
		return nil, false, fmt.Errorf("nothing to choose from")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return numberListPick(items, title, multi)
	}
	m := newListModel(items, g, title, multi)
	prog := tea.NewProgram(m, tea.WithOutput(os.Stderr), tea.WithInput(os.Stdin))
	res, err := prog.Run()
	if err != nil {
		return nil, false, fmt.Errorf("selection failed: %w", err)
	}
	lm := res.(listModel)
	if lm.cancelled {
		return nil, true, nil
	}
	if multi {
		out := make([]int, 0, len(lm.selected))
		for i := range lm.cands {
			if lm.selected[i] {
				out = append(out, i)
			}
		}
		return out, false, nil
	}
	if lm.chosen < 0 {
		return nil, true, nil
	}
	return []int{lm.chosen}, false, nil
}

type listModel struct {
	title     string
	cands     []string
	groups    *listGroups // nil when the caller passed no grouping
	tabs      []string    // distinct groups; index 0 is "" = all
	tabIdx    int         // selected tab (←/→)
	filtered  []int
	query     string
	cursor    int
	offset    int
	height    int
	width     int
	multi     bool
	selected  map[int]bool
	chosen    int // single-select result, -1 if none
	cancelled bool
}

func newListModel(items []string, g *listGroups, title string, multi bool) listModel {
	m := listModel{
		title:    title,
		cands:    items,
		groups:   g,
		tabs:     distinctGroups(g),
		height:   pickerViewport,
		width:    100,
		multi:    multi,
		selected: map[int]bool{},
		chosen:   -1,
	}
	if w, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil && w > 0 {
		m.width = w
	}
	m.refilter()
	return m
}

// distinctGroups returns the sorted distinct group labels with "" (all) first,
// mirroring the server picker's DC tabs. A caller with no grouping, or with one
// group covering everything, gets a single entry and no tab row: cycling
// between "all" and "all but named" is a control that does nothing.
func distinctGroups(g *listGroups) []string {
	if g == nil {
		return []string{""}
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range g.of {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return append([]string{""}, out...)
}

// groupOf reports the group of candidate i, tolerating a short or absent slice
// so callers are not forced to pad it.
func (m listModel) groupOf(i int) string {
	if m.groups == nil || i >= len(m.groups.of) {
		return ""
	}
	return m.groups.of[i]
}

// groupName is the label for the tab row.
func (m listModel) groupName() string {
	if m.groups == nil || m.groups.name == "" {
		return "group"
	}
	return m.groups.name
}

func (m listModel) Init() tea.Cmd { return nil }

func (m *listModel) refilter() {
	q := strings.ToLower(strings.TrimSpace(m.query))
	tab := m.tabs[m.tabIdx] // "" = all groups
	m.filtered = m.filtered[:0]
	for i, c := range m.cands {
		if tab != "" && m.groupOf(i) != tab {
			continue
		}
		if q == "" || strings.Contains(strings.ToLower(c), q) {
			m.filtered = append(m.filtered, i)
		}
	}
	m.cursor = 0
	m.offset = 0
}

func (m *listModel) clampScroll() {
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

func (m listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if msg.Width > 0 {
			m.width = msg.Width
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			m.cancelled = true
			return m, tea.Quit
		case tea.KeyEnter:
			if !m.multi && len(m.filtered) > 0 {
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
			if len(m.tabs) > 1 {
				m.tabIdx = (m.tabIdx - 1 + len(m.tabs)) % len(m.tabs)
				m.refilter()
			}
			return m, nil
		case tea.KeyRight:
			if len(m.tabs) > 1 {
				m.tabIdx = (m.tabIdx + 1) % len(m.tabs)
				m.refilter()
			}
			return m, nil
		case tea.KeySpace:
			if m.multi && len(m.filtered) > 0 {
				i := m.filtered[m.cursor]
				m.selected[i] = !m.selected[i]
				return m, nil
			}
			// single mode: treat space as filter input
			m.query += " "
			m.refilter()
			return m, nil
		case tea.KeyBackspace:
			if m.query != "" {
				r := []rune(m.query)
				m.query = string(r[:len(r)-1])
				m.refilter()
			}
			return m, nil
		case tea.KeyRunes:
			m.query += string(msg.Runes)
			m.refilter()
			return m, nil
		}
	}
	return m, nil
}

func (m listModel) View() string {
	var b strings.Builder
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
	grouped := len(m.tabs) > 2
	switch {
	case m.multi:
		b.WriteString(pickDimStyle.Render(fmt.Sprintf("↑↓ move, space toggle, type filter, enter confirm, esc cancel  (%d selected)", len(m.selected))))
	case grouped:
		b.WriteString(pickDimStyle.Render("↑↓ move, ←→ " + m.groupName() + ", type to filter, enter confirm, esc cancel"))
	default:
		b.WriteString(pickDimStyle.Render("↑↓ move, type to filter, enter confirm, esc cancel"))
	}
	b.WriteString("\n")
	if grouped {
		label := m.tabs[m.tabIdx]
		if label == "" {
			label = "all " + m.groupName() + "s"
		}
		b.WriteString(pickDimStyle.Render(m.groupName() + " ‹ "))
		b.WriteString(pickCursorStyle.Render(label))
		b.WriteString(pickDimStyle.Render(fmt.Sprintf(" ›  %d/%d", m.tabIdx+1, len(m.tabs))))
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

func (m listModel) renderRow(i int) string {
	ci := m.filtered[i]
	label := m.cands[ci]
	// Radio dots in single mode, checkboxes in multi — the same marks the server
	// picker uses, so `vctl ssh` and `vctl delete` do not look like two tools.
	// Both spellings occupy the same width within a mode, which is what keeps the
	// labels aligned across rows.
	mark := "○"
	switch {
	case m.multi && m.selected[ci]:
		mark = "[x]"
	case m.multi:
		mark = "[ ]"
	case i == m.cursor:
		mark = "●"
	}
	if i == m.cursor {
		return pickCursorStyle.Render("› "+mark) + " " + pickSelectedStyle.Render(label)
	}
	return pickDimStyle.Render("  "+mark+" ") + label
}

// numberListPick is the non-TTY fallback. Single: one number. Multi: a
// comma/space separated list of numbers (empty = none).
func numberListPick(items []string, title string, multi bool) ([]int, bool, error) {
	ui.Section(os.Stderr, title)
	for i, c := range items {
		fmt.Fprintf(os.Stderr, "  %2d  %s\n", i+1, c)
	}
	if multi {
		fmt.Fprint(os.Stderr, ui.Muted("numbers (comma/space separated, empty=none): "))
	} else {
		fmt.Fprint(os.Stderr, ui.Muted("number: "))
	}
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		if multi {
			return nil, false, nil
		}
		return nil, true, nil
	}
	fields := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' })
	var out []int
	for _, f := range fields {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 || n > len(items) {
			return nil, false, fmt.Errorf("invalid selection %q", f)
		}
		out = append(out, n-1)
		if !multi {
			break
		}
	}
	return out, false, nil
}
