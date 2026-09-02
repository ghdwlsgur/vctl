package openstack

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The browser's state and what moves it: which pane has the keys, which rows
// the filter leaves, and what each key does to that.
//
// Nothing here draws. Every function is either a question about the current
// state or a transition to the next one, which is what lets the tests drive a
// model through a sequence of keys and assert on where the cursor ended up
// without rendering a frame. See openstack_explore_view.go for the drawing.

// connectMode is how a confirmed connect proceeds once the login user is known.
type connectMode int

const (
	// modeSubshell suspends the screen and runs `vctl ssh --vm` with a PTY —
	// for the visit that needs an editor or a pager. Bound to `c`.
	modeSubshell connectMode = iota
	// modeConsole opens the inline pane under the VM's detail — for the visit
	// that is three commands and a look at their output. Bound to enter.
	modeConsole
)

// exploreConsole is the inline pane's state: whose machine, the scrollback,
// and the command being typed. It hangs off the model as a pointer so a
// background command's output lands in the same pane the keys are editing.
type exploreConsole struct {
	vm      *store.Instance
	user    string
	lines   []string
	input   string
	running bool

	// history holds submitted commands; histIdx == len(history) means the
	// prompt is on a fresh line. Up/down walk it the way a shell does.
	history []string
	histIdx int
}

// consoleOutput carries one finished command's output back to the pane.
type consoleOutput struct {
	out  string
	code int
	err  error
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
	// lines so it can scroll. detailVM is set when the overlay shows a VM, so
	// `c` knows what to connect to.
	detail    []string
	detailTop int
	detailOf  string
	detailVM  *store.Instance

	// carry is printed after the screen is restored — see runExplore.
	carry []string
	err   error

	// The pending connect: on a VM, `c` (full subshell) or enter-in-detail
	// (inline console) first asks for a login user — Nova does not record one.
	// The prompt is open exactly while connectVM is set; enter consumes it, so
	// there is no separate boolean to keep in sync.
	userInput   string
	connectVM   *store.Instance
	connectMode connectMode
	connectNote string // what the last subshell said on the way out
	defaultUser string

	// console is the inline pane under a VM's detail: a prompt, and the output
	// of every command run so far. Commands run one at a time through the same
	// pipeline as `vctl ssh --vm` exec — a fresh Vault-signed certificate and
	// an audit row per command — via execVM, injected so tests never dial.
	console *exploreConsole
	execVM  func(v *store.Instance, user, command string) (string, int, error)

	// refresh reads the fleet again. Held as a function so the model can be
	// driven in a test without a database, and called from a tea.Cmd so the
	// read never blocks a keypress.
	refresh    func() (exploreData, error)
	refreshing bool
	// refreshErr is a refresh that did not land. Shown rather than returned:
	// what is already on screen is still worth reading, and a browser that
	// exits because its background read failed loses the reader's place over
	// something they did not ask for.
	refreshErr error
}

func newExploreModel(d exploreData) exploreModel {
	return exploreModel{data: d, width: 100, height: 30}
}

// exploreRefreshed carries a background read back to the screen.
type exploreRefreshed struct {
	data exploreData
	err  error
}

// refreshCmd runs the read off the key path.
func (m exploreModel) refreshCmd() tea.Cmd {
	read := m.refresh
	if read == nil {
		return nil
	}
	return func() tea.Msg {
		data, err := read()
		return exploreRefreshed{data: data, err: err}
	}
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

// Init starts the correcting read when the screen went up on a stored one.
func (m exploreModel) Init() tea.Cmd {
	if !m.refreshing {
		return nil
	}
	return m.refreshCmd()
}

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
	case exploreRefreshed:
		return m.onRefreshed(msg), nil
	case tea.KeyMsg:
		return m.onKey(msg)
	case exploreConnectDone:
		if msg.err != nil {
			m.connectNote = fmt.Sprintf("%s: %s", msg.vm, strutil.OneLine(msg.err.Error()))
		}
		return m, nil
	case consoleOutput:
		return m.onConsoleOutput(msg), nil
	}
	return m, nil
}

// onRefreshed swaps in a read that landed, keeping the reader where they were.
//
// The selection is restored by name, not by index. Rows move between readings —
// a VM is deleted, a host is added — and a cursor put back on position 12 of a
// list that changed points at a different machine, which is worse than a cursor
// that moved.
func (m exploreModel) onRefreshed(msg exploreRefreshed) exploreModel {
	m.refreshing = false
	if msg.err != nil {
		m.refreshErr = msg.err
		return m
	}
	was := m.selection()
	m.data, m.refreshErr = msg.data, nil
	m.restoreSelection(was)
	return m
}

// exploreSelection is what the cursor was on, named rather than numbered.
type exploreSelection struct{ farm, row string }

func (m exploreModel) selection() exploreSelection {
	var s exploreSelection
	if f, ok := m.currentFarm(); ok {
		s.farm = f.ID
	}
	if m.kind == kindHosts {
		if hosts := m.visibleHosts(); len(hosts) > 0 {
			s.row = hosts[clampIndex(m.rowCur, len(hosts))].Hostname
		}
		return s
	}
	if vms := m.visibleVMs(); len(vms) > 0 {
		s.row = vms[clampIndex(m.rowCur, len(vms))].InstanceID
	}
	return s
}

// restoreSelection puts the cursor back on the same machine, or at the top when
// it is no longer there — which is itself the news that it is gone.
func (m *exploreModel) restoreSelection(s exploreSelection) {
	m.farmCur, m.rowCur, m.rowTop = 0, 0, 0
	if s.farm != "" {
		for i, f := range m.visibleFarms() {
			if f.ID == s.farm {
				m.farmCur = i
				break
			}
		}
	}
	if s.row == "" {
		return
	}
	if m.kind == kindHosts {
		for i, h := range m.visibleHosts() {
			if h.Hostname == s.row {
				m.rowCur = i
				break
			}
		}
	} else {
		for i, v := range m.visibleVMs() {
			if v.InstanceID == s.row {
				m.rowCur = i
				break
			}
		}
	}
	m.scrollRows()
}

func (m exploreModel) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Typing a filter comes first: every shortcut below is also a letter, and a
	// browser that quits because somebody filtered for "quay" is a browser
	// nobody types into twice.
	if m.typing {
		return m.onFilterKey(msg)
	}
	if m.askingUser() {
		return m.onConnectKey(msg)
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
		if m.data.NeedsLogin {
			return m, nil
		}
		// Deliberately not on a timer. A screen that re-reads on its own moves
		// the row somebody was about to open, and a browser nobody is looking at
		// would keep a database busy for no one.
		if m.refreshing {
			return m, nil
		}
		m.refreshing, m.refreshErr = true, nil
		return m, m.refreshCmd()
	case "c":
		if m.kind == kindVMs && m.focus == paneRows {
			if vms := m.visibleVMs(); len(vms) > 0 {
				v := vms[clampIndex(m.rowCur, len(vms))]
				m.startConnect(&v, modeSubshell)
			}
		}
		return m, nil
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

// startConnect opens the login-user prompt for one VM. Nova records no login
// user, so the one thing the browser cannot answer for you is asked, prefilled
// with the config default.
func (m *exploreModel) startConnect(v *store.Instance, mode connectMode) {
	m.userInput = m.defaultUser
	m.connectVM = v
	m.connectMode = mode
	m.connectNote = ""
}

// askingUser reports whether the login-user prompt is open.
func (m exploreModel) askingUser() bool { return m.connectVM != nil }

// onConnectKey edits the login user for the pending connect. Enter proceeds —
// into the inline console or the full subshell, whichever asked — and esc
// forgets the whole idea.
func (m exploreModel) onConnectKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		// Enter consumes the pending VM either way, which is what closes the
		// prompt — the prompt is open exactly while connectVM is set.
		v := m.connectVM
		m.connectVM = nil
		user := strings.TrimSpace(m.userInput)
		if v == nil || user == "" {
			return m, nil
		}
		if m.connectMode == modeConsole {
			m.console = &exploreConsole{vm: v, user: user}
			return m, nil
		}
		return m, m.connectCmd(v, user)
	case tea.KeyEsc:
		m.connectVM = nil
		return m, nil
	case tea.KeyCtrlC:
		return m, tea.Quit
	}
	m.userInput, _ = editLine(m.userInput, msg)
	return m, nil
}

// connectCmd suspends the browser and runs `vctl ssh --vm` attached to the
// terminal, resuming when the shell exits. It execs this same binary rather
// than dialing in-process: the subshell then IS the vctl ssh command — same
// RBAC gate, same audit row, same jump logic — and cannot drift from it.
// --allow-stale is passed because the browser already showed the record's age
// beside the address; the flag exists to force that acknowledgment on people
// connecting blind.
func (m exploreModel) connectCmd(v *store.Instance, user string) tea.Cmd {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	args := []string{"ssh", "--vm", v.InstanceID, "--user", user, "--allow-stale"}
	if v.DeploymentID != "" {
		args = append(args, "--farm", v.DeploymentID)
	}
	return tea.ExecProcess(exec.Command(exe, args...), func(err error) tea.Msg {
		return exploreConnectDone{vm: NameOrID(*v), err: err}
	})
}

// exploreConnectDone reports the subshell's exit back to the resumed screen.
type exploreConnectDone struct {
	vm  string
	err error
}

// onConsoleKey edits and submits the inline console's command line. Only esc
// leaves — every letter, q included, is something somebody types into a shell.
func (m exploreModel) onConsoleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := m.console
	switch msg.Type {
	case tea.KeyEsc:
		m.console = nil
		return m, nil
	case tea.KeyCtrlC:
		// ^C in a prompt means "abandon this line", not "kill the browser".
		if c.running || c.input != "" {
			c.input = ""
			return m, nil
		}
		m.console = nil
		return m, nil
	case tea.KeyEnter:
		command := strings.TrimSpace(c.input)
		if command == "" || c.running {
			return m, nil
		}
		c.lines = append(c.lines, consolePrompt(c)+command)
		if n := len(c.history); n == 0 || c.history[n-1] != command {
			c.history = append(c.history, command)
		}
		c.histIdx = len(c.history)
		c.input = ""
		c.running = true
		return m, m.consoleRun(command)
	case tea.KeyUp:
		if c.histIdx > 0 {
			c.histIdx--
			c.input = c.history[c.histIdx]
		}
		return m, nil
	case tea.KeyDown:
		if c.histIdx < len(c.history) {
			c.histIdx++
			if c.histIdx == len(c.history) {
				c.input = ""
			} else {
				c.input = c.history[c.histIdx]
			}
		}
		return m, nil
	}
	c.input, _ = editLine(c.input, msg)
	return m, nil
}

// consolePrompt is the echoed prompt for the scrollback, shaped like the shell
// the pane stands in for.
func consolePrompt(c *exploreConsole) string {
	return c.user + "@" + NameOrID(*c.vm) + " $ "
}

// consoleRun executes one command off the key path. Each command goes through
// the same pipeline as `vctl ssh --vm` exec — a fresh Vault-signed certificate
// and an audit row — via the injected execVM.
func (m exploreModel) consoleRun(command string) tea.Cmd {
	run, c := m.execVM, m.console
	if run == nil || c == nil {
		return func() tea.Msg {
			return consoleOutput{err: fmt.Errorf("console has no executor wired")}
		}
	}
	vm, user := c.vm, c.user
	return func() tea.Msg {
		out, code, err := run(vm, user, command)
		return consoleOutput{out: out, code: code, err: err}
	}
}

// onConsoleOutput appends one finished command's output to the pane.
func (m exploreModel) onConsoleOutput(msg consoleOutput) exploreModel {
	c := m.console
	if c == nil {
		return m // pane closed while the command ran; the audit row still exists
	}
	c.running = false
	if out := strings.TrimRight(msg.out, "\n"); out != "" {
		c.lines = append(c.lines, strings.Split(out, "\n")...)
	}
	if msg.err != nil {
		c.lines = append(c.lines, ui.Fail(strutil.OneLine(msg.err.Error())))
	} else if msg.code != 0 {
		c.lines = append(c.lines, ui.Muted(fmt.Sprintf("exit %d", msg.code)))
	}
	// The pane only ever shows the tail, so the scrollback must not grow with
	// every journalctl dump for the browser's lifetime. Reslice-with-copy so
	// the dropped head's backing array is actually released.
	if n := len(c.lines); n > consoleScrollback {
		c.lines = append([]string(nil), c.lines[n-consoleScrollback:]...)
	}
	return m
}

// consoleScrollback is how many lines the pane keeps. Far more than it can
// show, far less than a dmesg dump; the access log is the archive.
const consoleScrollback = 400

// editLine applies one key to a line under edit, reporting whether the key
// was an editing key. One editor for the filter, the connect prompt and the
// console — three hand-rolled copies had already diverged (one silently
// dropped the space key).
func editLine(s string, msg tea.KeyMsg) (string, bool) {
	switch msg.Type {
	case tea.KeyBackspace:
		if r := []rune(s); len(r) > 0 {
			return string(r[:len(r)-1]), true
		}
		return s, true
	case tea.KeySpace:
		return s + " ", true
	case tea.KeyRunes:
		return s + string(msg.Runes), true
	}
	return s, false
}

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
	}
	if v, ok := editLine(m.activeFilter(), msg); ok {
		m.setFilter(v)
	}
	return m, nil
}

func (m exploreModel) onDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.console != nil {
		return m.onConsoleKey(msg)
	}
	switch msg.String() {
	case "esc", "q":
		m.detail, m.detailTop, m.detailOf, m.detailVM = nil, 0, "", nil
		return m, nil
	case "enter":
		// On a VM's detail, enter opens the console under it — the detail is
		// where somebody reads the address and decides to act on it. On a
		// host's detail it closes, as enter always did.
		if m.detailVM != nil {
			m.startConnect(m.detailVM, modeConsole)
			return m, nil
		}
		m.detail, m.detailTop, m.detailOf = nil, 0, ""
		return m, nil
	case "c":
		// The full subshell (PTY: editors, pagers) from the same place.
		if m.detailVM != nil {
			m.startConnect(m.detailVM, modeSubshell)
		}
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
		m.detailVM = nil
	default:
		vms := m.visibleVMs()
		if len(vms) == 0 {
			return
		}
		v := vms[clampIndex(m.rowCur, len(vms))]
		renderVMShow(&buf, v, m.data.Names, m.data.Nets, now)
		m.detailOf = NameOrID(v)
		m.detailVM = &v
	}
	m.detail = strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	m.detailTop = 0
}
