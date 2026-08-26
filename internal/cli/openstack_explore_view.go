package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/timing"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// Drawing the browser: the two panes, the column layout, the detail overlay.
//
// Everything here reads the model and returns a string. Nothing decides what is
// selected or what a key means — that is openstack_explore_model.go.
//
// Every method below takes its model by value, and that is the property worth
// keeping rather than a filing decision: the renderer cannot move a cursor. It
// calls clampIndex to find which row is current, and clamping to read is not
// clamping to store — a pointer receiver here would let a width change edit the
// selection it is drawing.

// Layout constants. The left pane is fixed because a deployment name is short
// and predictable; every column that varies is on the right.
const (
	farmPaneWidth = 26
	chromeLines   = 5 // title, breathing room, pane heading, column heading, footer
)

var (
	exploreTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	exploreHeadingStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))
	exploreCursorStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	exploreFocusStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	exploreDimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	// Not muted, unlike everything else on that line: a refresh that failed is
	// the reason the age beside it stopped moving.
	exploreWarnStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
)

// bodyHeight is the number of lines the panes get.
func (m exploreModel) bodyHeight() int {
	h := m.height - chromeLines
	if h < 3 {
		return 3
	}
	return h
}

// rowsHeight is how many data rows the row pane can actually show, and it is the
// one number both the renderer and the scroller must agree on. The pane gets
// bodyHeight()+1 lines (see View); two go to the pane heading and column header
// and one is reserved for the "N–M of Z" position line, so the rest are rows.
// The renderer used bodyHeight()-1 while scrollRows used bodyHeight(): the row
// at the very bottom of the window was inside what the scroller kept visible but
// past what the renderer drew, so it vanished and enter opened an off-screen row.
func (m exploreModel) rowsHeight() int {
	if h := m.bodyHeight() - 2; h > 1 {
		return h
	}
	return 1
}

func (m exploreModel) rowPaneWidth() int {
	w := m.width - farmPaneWidth - 3
	if w < 20 {
		return 20
	}
	return w
}

func (m exploreModel) View() string {
	defer timing.Start("render")()
	if len(m.detail) > 0 {
		return m.detailView()
	}
	var b strings.Builder
	b.WriteString(m.clip(m.titleBar()) + "\n\n")

	farmLines := m.farmPaneLines()
	rowLines := m.rowPaneLines()
	for i := 0; i < m.bodyHeight()+1; i++ {
		left := ""
		if i < len(farmLines) {
			left = farmLines[i]
		}
		right := ""
		if i < len(rowLines) {
			right = rowLines[i]
		}
		b.WriteString(m.clip(ui.PadRight(left, farmPaneWidth)+exploreDimStyle.Render(" │ ")+right) + "\n")
	}
	b.WriteString(m.clip(m.footer()))
	return b.String()
}

// clip is the last word on width.
//
// Every piece below budgets itself, and this is here anyway: one line a column
// too wide wraps, a wrapped line pushes the rest of the frame down, and from
// then on the screen is nonsense. Being wrong about a width is easy — being
// wrong about it here is invisible until somebody with a narrow terminal opens
// the thing.
func (m exploreModel) clip(s string) string {
	return ui.Truncate(s, m.width)
}

// titleBar says what is loaded and how old it is. A browser reading a snapshot
// has to say so — the whole screen is as current as this line claims.
func (m exploreModel) titleBar() string {
	hosts, vms := 0, 0
	for _, hs := range m.data.Hosts {
		hosts += len(hs)
	}
	for _, vs := range m.data.VMs {
		vms += len(liveInstances(vs))
	}
	head := exploreTitleStyle.Render("OPENSTACK")
	detail := fmt.Sprintf("%d farms · %d hosts · %d VMs · %s",
		len(m.data.Farms), hosts, vms, m.freshness())
	line := head + "  " + ui.Muted(detail)
	if m.refreshErr != nil {
		line += "  " + exploreWarnStyle.Render("refresh failed: "+strutil.OneLine(m.refreshErr.Error()))
	}
	return line
}

// freshness is the claim everything else on the screen rests on.
//
// A stored reading says it is stored. The two are the same rows and cannot be
// told apart by looking at them, so the difference has to be written down: one
// was true when it was read and the other was true a moment ago.
func (m exploreModel) freshness() string {
	elapsed := time.Since(m.data.ReadAt)
	if elapsed < 0 {
		elapsed = 0
	}
	age := strutil.CompactDuration(elapsed)
	when := age + " ago"
	if elapsed < time.Minute {
		when = "just now"
	}
	what := "read " + when
	if m.data.Cached {
		what = "cached · " + age + " old"
		if elapsed < time.Minute {
			what = "cached · just now"
		}
	}
	if m.refreshing {
		what += " · reading…"
	}
	if m.data.NeedsLogin {
		what += " · run `vctl login` to refresh"
	}
	return what
}

func (m exploreModel) farmPaneLines() []string {
	farms := m.visibleFarms()
	title := "FARMS"
	if m.farmFilter != "" {
		title += " /" + m.farmFilter
	}
	out := []string{paneHeading(ui.Truncate(title, farmPaneWidth), m.focus == paneFarms)}
	for i, f := range farms {
		name := f.Name
		if name == "" {
			name = f.ID
		}
		count := fmt.Sprintf("%dH %dV", len(m.data.Hosts[f.ID]), len(liveInstances(m.data.VMs[f.ID])))
		nameWidth := max(6, farmPaneWidth-lipgloss.Width(count)-3)
		text := ui.PadRight(ui.Truncate(name, nameWidth), nameWidth) + " " + ui.Muted(count)
		out = append(out, m.cursorLine(text, i == clampIndex(m.farmCur, len(farms)), m.focus == paneFarms))
	}
	if len(farms) == 0 {
		out = append(out, ui.Muted("  no match"))
	}
	return out
}

func paneHeading(s string, active bool) string {
	if active {
		return exploreTitleStyle.Render(s)
	}
	return exploreHeadingStyle.Render(s)
}

// cursorLine marks the selected row, and marks it differently in the pane that
// is not taking keys — otherwise two rows look equally selected and the arrow
// keys appear to move the wrong one.
func (m exploreModel) cursorLine(text string, selected, focused bool) string {
	switch {
	case selected && focused:
		return exploreCursorStyle.Render("› ") + exploreFocusStyle.Render(text)
	case selected:
		return exploreDimStyle.Render("· ") + exploreFocusStyle.Render(text)
	default:
		return "  " + text
	}
}

// exploreColumns is one table's shape: fixed widths, and one column that takes
// whatever is left.
type exploreColumns struct {
	titles []string
	widths []int // 0 means "take the remaining space"
}

var (
	vmColumns = exploreColumns{
		titles: []string{"NAME", "PROJECT", "STATE", "ADDRESS", "HOST"},
		widths: []int{0, 16, 12, 16, 14},
	}
	hostColumns = exploreColumns{
		titles: []string{"HOST", "ROLES", "RELEASE", "SEEN", ""},
		widths: []int{0, 22, 9, 6, 18},
	}
)

// layout resolves the flexible column against the space there is, and drops
// columns from the right when even the minimum will not fit.
//
// Dropping rather than squeezing, because a column narrowed to four characters
// is not a column — and the heading row still names what is left, so nothing
// disappears without saying so.
func (c exploreColumns) layout(total int) ([]string, []int) {
	const gap, minFlex = 2, 12
	titles, widths := append([]string(nil), c.titles...), append([]int(nil), c.widths...)
	for {
		fixed := 0
		for _, w := range widths {
			fixed += w
		}
		gaps := gap * (len(widths) - 1)
		if flex := total - fixed - gaps; flex >= minFlex || len(widths) <= 2 {
			for i, w := range widths {
				if w == 0 {
					widths[i] = max(minFlex, flex)
				}
			}
			return titles, widths
		}
		titles, widths = titles[:len(titles)-1], widths[:len(widths)-1]
	}
}

func (c exploreColumns) render(cells []string, total int) string {
	titles, widths := c.layout(total)
	parts := make([]string, 0, len(titles))
	for i := range titles {
		if i >= len(cells) {
			break
		}
		parts = append(parts, ui.PadRight(ui.Truncate(cells[i], widths[i]), widths[i]))
	}
	return strings.TrimRight(strings.Join(parts, "  "), " ")
}

func (c exploreColumns) header(total int) string {
	titles, widths := c.layout(total)
	parts := make([]string, 0, len(titles))
	for i, t := range titles {
		parts = append(parts, ui.PadRight(t, widths[i]))
	}
	return exploreHeadingStyle.Render(strings.TrimRight(strings.Join(parts, "  "), " "))
}

func (m exploreModel) rowPaneLines() []string {
	f, ok := m.currentFarm()
	if !ok {
		return []string{ui.Muted("nothing selected")}
	}
	cols, cells := m.rowCells()
	width := m.rowPaneWidth()

	kind := "VMS"
	if m.kind == kindHosts {
		kind = "HOSTS"
	}
	head := fmt.Sprintf("%s · %s", farmMenuTitle(f), kind)
	if m.rowFilter != "" {
		head += " /" + m.rowFilter
	}
	head += fmt.Sprintf(" (%d)", len(cells))
	note := m.farmNote(f)
	// The note is what makes every number on the rows worth trusting, so the
	// heading gives way to it rather than the other way round.
	head = ui.Truncate(head, max(8, width-lipgloss.Width(note)-2))
	out := []string{
		paneHeading(head, m.focus == paneRows) + "  " + ui.Muted(note),
		"  " + cols.header(width-2),
	}
	if len(cells) == 0 {
		out = append(out, ui.Muted("  nothing here"))
		return out
	}
	end := min(m.rowTop+m.rowsHeight(), len(cells))
	for i := m.rowTop; i < end; i++ {
		out = append(out, m.cursorLine(cols.render(cells[i], width-2),
			i == clampIndex(m.rowCur, len(cells)), m.focus == paneRows))
	}
	// The count is in the heading, so a partial window is visible there; this
	// says which part. The slot for it is reserved in rowsHeight, so it never
	// pushes a row off the bottom of the pane.
	if len(cells) > m.rowsHeight() {
		out = append(out, ui.Muted(fmt.Sprintf("  %d–%d of %d", m.rowTop+1, end, len(cells))))
	}
	return out
}

// farmNote is what the reconcile age says about everything else on the row.
func (m exploreModel) farmNote(f farmChoice) string {
	run, ok := m.data.Runs[f.ID]
	if !ok || run.SucceededAt == nil {
		return "never reconciled"
	}
	return "reconciled " + strutil.CompactDuration(time.Since(*run.SucceededAt)) + " ago"
}

func (m exploreModel) rowCells() (exploreColumns, [][]string) {
	now := time.Now()
	if m.kind == kindHosts {
		hosts := m.visibleHosts()
		out := make([][]string, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, []string{
				h.Hostname,
				rolesSummary(h.Roles, false),
				versionCell(h, false),
				ageCell(h, now),
				openStackNoteCell(h, now),
			})
		}
		return hostColumns, out
	}
	vms := m.visibleVMs()
	out := make([][]string, 0, len(vms))
	for _, v := range vms {
		out = append(out, []string{
			nameOrID(v),
			ui.Muted(vmProjectLabel(v)),
			vmStateCell(v),
			primaryAddress(v, m.data.Nets),
			ui.Muted(v.HypervisorHostname),
		})
	}
	return vmColumns, out
}

func (m exploreModel) detailView() string {
	var b strings.Builder
	// The freshness comes with it. The title bar that carried it is not on
	// screen here, and this is the view that shows a VM's addresses and offers
	// the line for reaching one — where somebody stops reading and starts
	// acting on what is in front of them.
	head := exploreTitleStyle.Render("▌ " + ui.Truncate(m.detailOf, 60))
	b.WriteString(m.clip(head+"  "+ui.Muted(m.freshness())) + "\n")
	h := m.bodyHeight() + 1
	end := min(m.detailTop+h, len(m.detail))
	for i := m.detailTop; i < end; i++ {
		b.WriteString(m.clip(m.detail[i]) + "\n")
	}
	for i := end - m.detailTop; i < h; i++ {
		b.WriteString("\n")
	}
	hint := "esc back · ↑↓ scroll · p keep on exit · q close"
	if len(m.detail) > h {
		hint = fmt.Sprintf("%d–%d of %d · ", m.detailTop+1, end, len(m.detail)) + hint
	}
	b.WriteString(m.clip(ui.Muted(hint)))
	return b.String()
}

func (m exploreModel) footer() string {
	if m.typing {
		return exploreCursorStyle.Render("/"+m.activeFilter()) +
			ui.Muted("   enter keep · esc clear")
	}
	// Dropped from the middle out: the two ends are the ones somebody needs
	// without being told, and a footer cut in half by the terminal edge tells
	// them nothing at all.
	keys := []string{
		"tab switch", "↑↓ move", "enter open", "v VMs", "s hosts",
		"/ filter", "r refresh", "q quit",
	}
	for len(keys) > 2 && lipgloss.Width(strings.Join(keys, " · ")) > m.width {
		keys = append(keys[:len(keys)-2], keys[len(keys)-1])
	}
	return ui.Muted(strings.Join(keys, " · "))
}

// liveInstances drops the VMs nova no longer lists.
//
// The store keeps them so a farm's assessment can count what went missing, and
// a browser is not a count: a list offering nine machines that are gone is a
// list somebody will try to connect to.
func liveInstances(in []store.Instance) []store.Instance {
	out := make([]store.Instance, 0, len(in))
	for _, v := range in {
		if v.MissingSince == nil {
			out = append(out, v)
		}
	}
	return out
}

func farmMenuTitle(f farmChoice) string {
	if f.Name != "" {
		return f.Name
	}
	return f.ID
}
