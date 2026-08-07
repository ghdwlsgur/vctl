package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// A two-pane browser over what the fleet has already reported: deployments on
// the left, the chosen one's hosts or VMs on the right, a detail view over the
// top of both.
//
// It exists because the data was only reachable by naming it. Hosts are
// `openstack --farm`, VMs are `openstack vm --farm`, a VM's detail is
// `vm show <uuid>` — three commands and an identifier nobody has memorised, in
// an order that is only obvious once you already know the answer. Moving a
// cursor asks the same questions without knowing any of it.
//
// Everything here reads the database and nothing else. No screen contacts a
// farm's control plane: that is `farm doctor`, it authenticates, and it can
// hang on a farm that is down — which is not a thing a browser may do. Two
// tests hold this, one for writes and one for the control plane.
//
// The detail screens are the individual commands' own renderers, so this and
// `openstack host` / `vm show` cannot drift into showing different facts about
// the same machine.
func openstackExploreCmd(env CommandEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "explore [deployment]",
		Aliases: []string{"browse", "ui"},
		Short:   "Browse deployments, hosts and VMs in one screen",
		Long: "Two panes: deployments on the left, the selected one's VMs or hosts on the right.\n\n" +
			"  tab      move between the panes        v / h   VMs or hosts on the right\n" +
			"  enter    open the row's detail         /       filter the focused pane\n" +
			"  r        re-read from the database     q       quit\n\n" +
			"Read-only, and it reads the database alone — nothing here contacts a farm's\n" +
			"control plane. Each detail screen is the same renderer the individual command\n" +
			"uses: `openstack host` and `vm show`.\n\n" +
			"A farm that is misbehaving is a different question, asked with\n" +
			"`vctl openstack farm doctor <deployment>`.\n\n" +
			"An argument selects that deployment at startup.",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: byPosition(completeFarm(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			// A full-screen program needs a screen. Naming the commands that
			// answer the same questions without one is more useful than
			// reporting the absence of a terminal.
			if !isTerminal() {
				return fmt.Errorf("explore is a full-screen browser and there is no terminal; " +
					"use 'vctl openstack farm list', 'vctl openstack --farm <f>' and " +
					"'vctl openstack vm --farm <f>' instead")
			}
			return env.withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				return runExplore(cmd.Context(), st, args)
			})
		},
	}
	return cmd
}

// runExplore reads, runs the screen, and reads again when the screen asks.
//
// Reloading by leaving and re-entering the program rather than from inside
// Update: a database call on the key path would stop the whole screen on a
// database that is slow, with no way to say so while it is stopped. What the
// reader had set up is carried across, so a reload shows as the numbers
// changing and nothing else.
func runExplore(ctx context.Context, st *store.Store, args []string) error {
	var (
		selected  string
		carryOver *exploreModel
	)
	for {
		// Before the screen, not on it. The first read of a session pays for a
		// Vault credential and four queries — measured at about ten seconds on
		// a cold path here — and an alternate screen that opens empty for that
		// long looks like a program that has hung. On stderr, so the alternate
		// screen wipes it the moment there is something to show.
		ui.Infof(os.Stderr, "reading the fleet…")
		data, err := loadExploreData(ctx, st)
		if err != nil {
			return err
		}
		if len(data.Farms) == 0 {
			ui.Warnf(os.Stderr, "no deployments yet. Run the node agents, then 'vctl openstack'.")
			return nil
		}
		if len(args) > 0 && selected == "" {
			// Resolved against the first reading, so a typo fails before the
			// screen opens rather than after.
			f, err := resolveFarm(data.Farms, args[0])
			if err != nil {
				return err
			}
			selected = f.ID
		}
		m := newExploreModel(data)
		if selected != "" {
			m.selectFarmID(selected)
		}
		if carryOver != nil {
			m.adoptView(*carryOver)
		}
		// The alternate screen, so the terminal somebody was working in comes
		// back exactly as they left it.
		res, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
		if err != nil {
			return err
		}
		final, ok := res.(exploreModel)
		if !ok {
			return nil
		}
		if final.err == errExploreReload {
			if f, ok := final.currentFarm(); ok {
				selected = f.ID
			}
			prev := final
			carryOver = &prev
			continue
		}
		// What was on screen at the end survives the screen. A VM's detail
		// carries the ssh line that reaches it, and an alternate screen that
		// restores on exit would take it back the moment somebody went to run
		// it.
		if len(final.carry) > 0 {
			fmt.Fprintln(os.Stdout, strings.Join(final.carry, "\n"))
		}
		return final.err
	}
}

// adoptView carries what the reader set up across a reload: which pane, which
// kind of row, the filters, the size. The cursor is not carried — the rows
// behind it may be different ones now, and a cursor left on row 12 of a list
// that changed is a worse guess than the top.
func (m *exploreModel) adoptView(prev exploreModel) {
	m.focus, m.kind = prev.focus, prev.kind
	m.farmFilter, m.rowFilter = prev.farmFilter, prev.rowFilter
	m.width, m.height = prev.width, prev.height
}

// exploreData is the whole picture, read once.
//
// One read for the fleet rather than one per farm: moving a cursor must not
// open a database connection, and a browser whose panes disagree because they
// were read seconds apart is worse than one that is a minute old and says so.
// `r` re-reads, which is the only way to be sure the screen is current.
type exploreData struct {
	Farms  []farmChoice
	Hosts  map[string][]store.OpenStackHost
	VMs    map[string][]store.Instance
	Names  map[string]string
	Runs   map[string]store.ReconcileRun
	Nets   []string
	ReadAt time.Time
}

func loadExploreData(ctx context.Context, st *store.Store) (exploreData, error) {
	out := exploreData{
		Hosts: map[string][]store.OpenStackHost{},
		VMs:   map[string][]store.Instance{},
		Nets:  operatorNetworks(),
	}
	// One transaction for the whole screen. This used to be four reads, two of
	// which the picker's own assembly then repeated — so the left pane's host
	// count and the right pane's VM list came from different instants.
	cat, err := loadVMCatalog(ctx, st)
	if err != nil {
		return out, err
	}
	out.Farms = cat.Farms()
	out.Names = cat.Names()
	out.Runs = map[string]store.ReconcileRun{}
	for _, f := range out.Farms {
		out.Hosts[f.ID] = f.Hosts
		out.VMs[f.ID] = cat.VMs(f.ID)
		if run := cat.Run(f.ID); run != nil {
			out.Runs[f.ID] = *run
		}
	}
	out.ReadAt = cat.ReadAt()
	return out, nil
}

// Which pane the keys go to.
type explorePane int

const (
	paneFarms explorePane = iota
	paneRows
)

// What the right pane is showing.
type exploreKind int

const (
	kindVMs exploreKind = iota
	kindHosts
)

type exploreModel struct {
	data exploreData

	width, height int
	focus         explorePane
	kind          exploreKind

	farmCur int
	rowCur  int
	rowTop  int

	// filter narrows the focused pane. Held per pane, because a filter that
	// followed the cursor between them would silently hide rows in the one
	// nobody is looking at.
	farmFilter, rowFilter string
	typing                bool

	// detail is the overlay: the individual command's own rendering, held as
	// lines so it can scroll.
	detail    []string
	detailTop int
	detailOf  string

	// carry is printed after the screen is restored — see runExplore.
	carry []string
	err   error
}

func newExploreModel(d exploreData) exploreModel {
	return exploreModel{data: d, width: 100, height: 30}
}

func (m *exploreModel) selectFarmID(id string) {
	for i, f := range m.visibleFarms() {
		if f.ID == id {
			m.farmCur = i
			m.focus = paneRows
			return
		}
	}
}

func (m exploreModel) Init() tea.Cmd { return nil }

// visibleFarms is the left pane's contents after its filter.
func (m exploreModel) visibleFarms() []farmChoice {
	if m.farmFilter == "" {
		return m.data.Farms
	}
	out := make([]farmChoice, 0, len(m.data.Farms))
	for _, f := range m.data.Farms {
		if matchesFilter(m.farmFilter, f.ID, f.Name, f.Region, farmShape(f.Hosts, true)) {
			out = append(out, f)
		}
	}
	return out
}

func (m exploreModel) currentFarm() (farmChoice, bool) {
	farms := m.visibleFarms()
	if len(farms) == 0 {
		return farmChoice{}, false
	}
	i := clampIndex(m.farmCur, len(farms))
	return farms[i], true
}

// visibleHosts and visibleVMs are the right pane's contents after its filter.
func (m exploreModel) visibleHosts() []store.OpenStackHost {
	f, ok := m.currentFarm()
	if !ok {
		return nil
	}
	all := m.data.Hosts[f.ID]
	if m.rowFilter == "" {
		return all
	}
	out := make([]store.OpenStackHost, 0, len(all))
	for _, h := range all {
		if matchesFilter(m.rowFilter, h.Hostname, h.DC, strings.Join(h.Roles, " ")) {
			out = append(out, h)
		}
	}
	return out
}

func (m exploreModel) visibleVMs() []store.Instance {
	f, ok := m.currentFarm()
	if !ok {
		return nil
	}
	all := liveInstances(m.data.VMs[f.ID])
	if m.rowFilter == "" {
		return all
	}
	out := make([]store.Instance, 0, len(all))
	for _, v := range all {
		addrs := make([]string, 0, len(v.Addresses))
		for _, a := range v.Addresses {
			addrs = append(addrs, a.Address)
		}
		if matchesFilter(m.rowFilter, v.Name, v.InstanceID, vmProjectLabel(v),
			v.HypervisorHostname, strings.Join(addrs, " ")) {
			out = append(out, v)
		}
	}
	return out
}

func (m exploreModel) rowCount() int {
	if m.kind == kindHosts {
		return len(m.visibleHosts())
	}
	return len(m.visibleVMs())
}

// matchesFilter is a case-insensitive substring over every field a row is
// recognised by. Substring rather than prefix: somebody filtering VMs knows
// "worker", not what the name starts with.
func matchesFilter(q string, fields ...string) bool {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return true
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func clampIndex(i, n int) int {
	if n == 0 {
		return 0
	}
	if i < 0 {
		return 0
	}
	if i >= n {
		return n - 1
	}
	return i
}

func (m exploreModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m exploreModel) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Typing a filter comes first: every shortcut below is also a letter, and a
	// browser that quits because somebody filtered for "quay" is a browser
	// nobody types into twice.
	if m.typing {
		return m.onFilterKey(msg)
	}
	if len(m.detail) > 0 {
		return m.onDetailKey(msg)
	}
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		if m.activeFilter() != "" {
			m.setFilter("")
			return m, nil
		}
		return m, tea.Quit
	case "tab", "shift+tab", "left", "right", "h", "l":
		// h and l are the vim pair for the same move. The right pane's kind is
		// on v and s instead, because a browser where "h" means both "left" and
		// "hosts" has to guess which one was meant.
		if msg.String() == "left" || msg.String() == "h" {
			m.focus = paneFarms
		} else if msg.String() == "right" || msg.String() == "l" {
			m.focus = paneRows
		} else if m.focus == paneFarms {
			m.focus = paneRows
		} else {
			m.focus = paneFarms
		}
		return m, nil
	case "up", "k":
		m.move(-1)
		return m, nil
	case "down", "j":
		m.move(1)
		return m, nil
	case "pgup":
		m.move(-m.rowsHeight())
		return m, nil
	case "pgdown":
		m.move(m.rowsHeight())
		return m, nil
	case "home", "g":
		m.moveTo(0)
		return m, nil
	case "end", "G":
		m.moveTo(1 << 30)
		return m, nil
	case "v":
		m.kind, m.rowCur, m.rowTop = kindVMs, 0, 0
		m.focus = paneRows
		return m, nil
	case "s":
		m.kind, m.rowCur, m.rowTop = kindHosts, 0, 0
		m.focus = paneRows
		return m, nil
	case "/":
		m.typing = true
		return m, nil
	case "r":
		// Deliberately not automatic. A screen that refreshes under the cursor
		// moves the row somebody was about to open.
		m.err = errExploreReload
		return m, tea.Quit
	case "enter":
		if m.focus == paneFarms {
			m.focus = paneRows
			m.rowCur, m.rowTop = 0, 0
			return m, nil
		}
		m.openDetail()
		return m, nil
	}
	return m, nil
}

// errExploreReload is how the model asks the caller to read again. Reloading
// inside Update would put a database call on the key path.
var errExploreReload = fmt.Errorf("reload")

func (m exploreModel) onFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter, tea.KeyEsc:
		m.typing = false
		if msg.Type == tea.KeyEsc {
			m.setFilter("")
		}
		return m, nil
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyBackspace:
		f := m.activeFilter()
		if f != "" {
			r := []rune(f)
			m.setFilter(string(r[:len(r)-1]))
		}
		return m, nil
	case tea.KeySpace:
		m.setFilter(m.activeFilter() + " ")
		return m, nil
	case tea.KeyRunes:
		m.setFilter(m.activeFilter() + string(msg.Runes))
		return m, nil
	}
	return m, nil
}

func (m exploreModel) onDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "enter", "q":
		m.detail, m.detailTop, m.detailOf = nil, 0, ""
		return m, nil
	case "ctrl+c":
		// Leaving from a detail keeps it: see runExplore.
		m.carry = m.detail
		return m, tea.Quit
	case "up", "k":
		m.detailTop = max(0, m.detailTop-1)
		return m, nil
	case "down", "j":
		m.detailTop = min(m.detailTop+1, max(0, len(m.detail)-m.bodyHeight()))
		return m, nil
	case "pgup":
		m.detailTop = max(0, m.detailTop-m.bodyHeight())
		return m, nil
	case "pgdown":
		m.detailTop = min(m.detailTop+m.bodyHeight(), max(0, len(m.detail)-m.bodyHeight()))
		return m, nil
	case "p":
		// Keep this one on the way out, so the ssh line survives the screen.
		m.carry = m.detail
		return m, tea.Quit
	}
	return m, nil
}

func (m exploreModel) activeFilter() string {
	if m.focus == paneFarms {
		return m.farmFilter
	}
	return m.rowFilter
}

func (m *exploreModel) setFilter(v string) {
	if m.focus == paneFarms {
		m.farmFilter = v
		m.farmCur = 0
	} else {
		m.rowFilter = v
	}
	m.rowCur, m.rowTop = 0, 0
}

func (m *exploreModel) move(delta int) {
	if m.focus == paneFarms {
		m.farmCur = clampIndex(m.farmCur+delta, len(m.visibleFarms()))
		// The right pane belongs to the farm under the cursor, so it starts at
		// the top rather than keeping a position that meant something else.
		m.rowCur, m.rowTop = 0, 0
		return
	}
	m.rowCur = clampIndex(m.rowCur+delta, m.rowCount())
	m.scrollRows()
}

func (m *exploreModel) moveTo(i int) {
	if m.focus == paneFarms {
		m.farmCur = clampIndex(i, len(m.visibleFarms()))
		m.rowCur, m.rowTop = 0, 0
		return
	}
	m.rowCur = clampIndex(i, m.rowCount())
	m.scrollRows()
}

// scrollRows keeps the cursor inside the visible window.
func (m *exploreModel) scrollRows() {
	h := m.rowsHeight()
	if h <= 0 {
		return
	}
	if m.rowCur < m.rowTop {
		m.rowTop = m.rowCur
	}
	if m.rowCur >= m.rowTop+h {
		m.rowTop = m.rowCur - h + 1
	}
	if m.rowTop < 0 {
		m.rowTop = 0
	}
}

// openDetail renders the selected row through the command that owns it.
func (m *exploreModel) openDetail() {
	var buf bytes.Buffer
	now := time.Now()
	switch m.kind {
	case kindHosts:
		hosts := m.visibleHosts()
		if len(hosts) == 0 {
			return
		}
		h := hosts[clampIndex(m.rowCur, len(hosts))]
		renderOpenStackHost(&buf, h, now)
		m.detailOf = h.Hostname
	default:
		vms := m.visibleVMs()
		if len(vms) == 0 {
			return
		}
		v := vms[clampIndex(m.rowCur, len(vms))]
		renderVMShow(&buf, v, m.data.Names, m.data.Nets, now)
		m.detailOf = nameOrID(v)
	}
	m.detail = strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	m.detailTop = 0
}

// Layout constants. The left pane is fixed because a deployment name is short
// and predictable; every column that varies is on the right.
const (
	farmPaneWidth = 26
	chromeLines   = 4 // title, pane heading, column heading, footer
)

var (
	exploreTitleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	exploreHeadingStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))
	exploreCursorStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	exploreFocusStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	exploreDimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// bodyHeight is the number of lines the panes get.
func (m exploreModel) bodyHeight() int {
	h := m.height - chromeLines
	if h < 3 {
		return 3
	}
	return h
}

func (m exploreModel) rowsHeight() int { return m.bodyHeight() }

func (m exploreModel) rowPaneWidth() int {
	w := m.width - farmPaneWidth - 3
	if w < 20 {
		return 20
	}
	return w
}

func (m exploreModel) View() string {
	if len(m.detail) > 0 {
		return m.detailView()
	}
	var b strings.Builder
	b.WriteString(m.clip(m.titleBar()) + "\n")

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
	head := exploreTitleStyle.Render("▌ vctl openstack")
	detail := fmt.Sprintf("· %d deployments · %d hosts · %d VMs · read %s ago",
		len(m.data.Farms), hosts, vms, ui.CompactDuration(time.Since(m.data.ReadAt)))
	return head + " " + ui.Muted(detail)
}

func (m exploreModel) farmPaneLines() []string {
	farms := m.visibleFarms()
	title := "DEPLOYMENTS"
	if m.farmFilter != "" {
		title += " /" + m.farmFilter
	}
	out := []string{exploreHeadingStyle.Render(ui.Truncate(title, farmPaneWidth))}
	for i, f := range farms {
		name := f.Name
		if name == "" {
			name = f.ID
		}
		count := fmt.Sprintf("%d", len(m.data.Hosts[f.ID]))
		text := ui.PadRight(ui.Truncate(name, farmPaneWidth-5), farmPaneWidth-5) + ui.Muted(count)
		out = append(out, m.cursorLine(text, i == clampIndex(m.farmCur, len(farms)), m.focus == paneFarms))
	}
	if len(farms) == 0 {
		out = append(out, ui.Muted("  no match"))
	}
	return out
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
		exploreHeadingStyle.Render(head) + "  " + ui.Muted(note),
		"  " + cols.header(width-2),
	}
	if len(cells) == 0 {
		out = append(out, ui.Muted("  nothing here"))
		return out
	}
	end := min(m.rowTop+m.rowsHeight()-1, len(cells))
	for i := m.rowTop; i < end; i++ {
		out = append(out, m.cursorLine(cols.render(cells[i], width-2),
			i == clampIndex(m.rowCur, len(cells)), m.focus == paneRows))
	}
	// The count is in the heading, so a partial window is visible there; this
	// says which part.
	if len(cells) > m.rowsHeight()-1 {
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
	return "reconciled " + ui.CompactDuration(time.Since(*run.SucceededAt)) + " ago"
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
	b.WriteString(m.clip(exploreTitleStyle.Render("▌ "+ui.Truncate(m.detailOf, 60))) + "\n")
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
		"tab pane", "↑↓ move", "enter detail", "v VMs", "s hosts",
		"/ filter", "r reload", "q quit",
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
