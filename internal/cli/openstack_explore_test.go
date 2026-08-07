package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// assertReadsOnly walks a file and fails on any call that records something.
//
// Two commands promise this in their help text — doctor and explore — and a
// promise the compiler does not check is a comment. Both are what somebody
// reaches for while a deployment is already misbehaving, which is exactly when
// nobody is thinking about what a "diagnostic" or a "browser" writes.
func assertReadsOnly(t *testing.T, filename, what string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	banned := map[string]bool{
		"ReconcileDeployment": true, "RecordReconcileRun": true,
		"RecordControlHosts": true, "ReplaceInstances": true,
		"SetDeploymentName": true, "SetDeploymentState": true,
		"ReplaceCapabilities": true, "RecordCapabilityError": true,
		"UpsertServerStatus": true,
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if banned[sel.Sel.Name] {
			t.Errorf("%s calls %s at %s; it is meant to read and nothing else",
				what, sel.Sel.Name, fset.Position(call.Pos()))
		}
		return true
	})
}

func TestExploreWritesNothing(t *testing.T) {
	assertReadsOnly(t, "openstack_explore.go", "explore")
}

// explore reads the database and nothing else.
//
// It offered a Diagnose screen at first, which reached the farm's Keystone and
// Nova. That makes a browser into something that authenticates against a
// control plane — a different act, with different failure modes, and one that
// can hang on a farm that is down. `farm doctor` is that command; keeping them
// apart is what lets this one promise it cannot make a farm's day worse.
func TestExploreNeverContactsAControlPlane(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "openstack_explore.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name == "diagnoseFarm" {
				t.Errorf("explore calls diagnoseFarm at %s; that is 'farm doctor', and it "+
					"talks to the farm's control plane", fset.Position(call.Pos()))
			}
		case *ast.SelectorExpr:
			if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "openstackapi" {
				t.Errorf("explore calls openstackapi.%s at %s; it reads what was already "+
					"collected", fn.Sel.Name, fset.Position(call.Pos()))
			}
		}
		return true
	})
}

// Without a terminal there is no full-screen anything, and the useful thing to
// say is which commands answer the same questions without one.
//
// The check runs before the store is opened and has to stay that way: failing
// on a login prompt that could not have been used is a worse error than the one
// it replaces.
func TestExploreRefusesWithoutATerminalAndNamesWhatToRunInstead(t *testing.T) {
	root := NewRoot(Dependencies{})
	cmd, _, err := root.Find([]string{"openstack", "explore"})
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	err = cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("explore ran with no terminal")
	}
	for _, want := range []string{"farm list", "--farm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}

// testExploreModel is two deployments with something in each, sized like a
// normal terminal.
func testExploreModel() exploreModel {
	at := time.Now().Add(-20 * time.Minute)
	d := exploreData{
		Farms: []farmChoice{
			{ID: "10.0.0.1:5000", Name: "seoul-a", Hosts: 2},
			{ID: "10.0.0.2:5000", Name: "seoul-b", Hosts: 1},
		},
		Hosts: map[string][]store.OpenStackHost{
			"10.0.0.1:5000": {
				{Hostname: "sre-srv-0001", Roles: []string{"compute"}, Detected: true},
				{Hostname: "sre-srv-0002", Roles: []string{"controller"}, Detected: true},
			},
			"10.0.0.2:5000": {{Hostname: "sre-srv-0009", Roles: []string{"compute"}, Detected: true}},
		},
		VMs: map[string][]store.Instance{
			"10.0.0.1:5000": {
				{DeploymentID: "10.0.0.1:5000", InstanceID: "u-1", Name: "bastion", Status: "ACTIVE",
					ProjectName: "platform", HypervisorHostname: "sre-srv-0001",
					Addresses: []store.InstanceAddress{{Address: "10.10.0.5"}}},
				{DeploymentID: "10.0.0.1:5000", InstanceID: "u-2", Name: "quay-registry", Status: "ACTIVE",
					ProjectName: "build", HypervisorHostname: "sre-srv-0002"},
			},
			"10.0.0.2:5000": {
				{DeploymentID: "10.0.0.2:5000", InstanceID: "u-9", Name: "worker-1", Status: "ACTIVE",
					ProjectName: "ai", HypervisorHostname: "sre-srv-0009"},
			},
		},
		Names:  map[string]string{"10.0.0.1:5000": "seoul-a", "10.0.0.2:5000": "seoul-b"},
		Runs:   map[string]store.ReconcileRun{"10.0.0.1:5000": {SucceededAt: &at}},
		ReadAt: time.Now(),
	}
	m := newExploreModel(d)
	m.width, m.height = 140, 40
	return m
}

// key sends one keypress and returns the model it produced.
func key(m exploreModel, s string) exploreModel {
	var msg tea.KeyMsg
	switch s {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		msg = tea.KeyMsg{Type: tea.KeyTab}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	case "up":
		msg = tea.KeyMsg{Type: tea.KeyUp}
	case "backspace":
		msg = tea.KeyMsg{Type: tea.KeyBackspace}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
	out, _ := m.Update(msg)
	return out.(exploreModel)
}

func keys(m exploreModel, ss ...string) exploreModel {
	for _, s := range ss {
		m = key(m, s)
	}
	return m
}

// The right pane belongs to the deployment under the cursor. Moving the left
// cursor and leaving the right pane showing the previous farm's machines is the
// one mistake this layout can make that a person would not notice.
func TestMovingTheFarmCursorChangesWhatTheRightPaneShows(t *testing.T) {
	m := testExploreModel()
	if got := m.visibleVMs(); len(got) != 2 || got[0].Name != "bastion" {
		t.Fatalf("first farm shows %d VMs", len(got))
	}
	m = key(m, "down")
	if got := m.visibleVMs(); len(got) != 1 || got[0].Name != "worker-1" {
		t.Fatalf("after moving down the pane shows %v", names(got))
	}
	if f, _ := m.currentFarm(); f.Name != "seoul-b" {
		t.Errorf("selected farm is %q", f.Name)
	}
}

// v and s are the two things the right pane can be. They also reset the cursor,
// because row 4 of the hosts is not row 4 of the VMs.
func TestTheRightPaneSwitchesBetweenVMsAndHosts(t *testing.T) {
	m := testExploreModel()
	m.rowCur = 1 // somewhere down the VM list
	m = key(m, "s")
	if m.kind != kindHosts {
		t.Fatal("s did not switch to hosts")
	}
	// Row 2 of the VMs is not row 2 of the hosts.
	if m.rowCur != 0 {
		t.Errorf("cursor stayed at %d after switching what the rows are", m.rowCur)
	}
	if got := len(m.visibleHosts()); got != 2 {
		t.Errorf("hosts = %d, want seoul-a's two", got)
	}
	// Choosing what the rows are also moves into them: "show me the hosts" is
	// followed by moving among the hosts, not among the deployments.
	if m.focus != paneRows {
		t.Error("s did not move into the rows it just filled")
	}
	// The hosts follow the deployment cursor as the VMs do — the pane belongs
	// to the farm, whichever kind of row it is showing. Back to the left pane
	// first, since the cursor is now in the list.
	if got := len(keys(m, "left", "down").visibleHosts()); got != 1 {
		t.Errorf("after moving to seoul-b the pane shows %d hosts, want 1", got)
	}
	if m = key(m, "v"); m.kind != kindVMs {
		t.Error("v did not switch back to VMs")
	}
}

// Filtering is the reason the shortcut keys cannot be read while typing: every
// one of them is a letter, and "quay" contains q.
func TestTypingAFilterDoesNotTriggerShortcuts(t *testing.T) {
	m := keys(testExploreModel(), "tab", "/", "q", "u", "a", "y")
	if !m.typing {
		t.Fatal("q ended the filter — it was read as quit")
	}
	if m.rowFilter != "quay" {
		t.Fatalf("filter = %q, want quay", m.rowFilter)
	}
	got := m.visibleVMs()
	if len(got) != 1 || got[0].Name != "quay-registry" {
		t.Fatalf("filter matched %v", names(got))
	}
	// Enter keeps it; esc clears it.
	m = key(m, "enter")
	if m.typing || m.rowFilter != "quay" {
		t.Errorf("enter should stop typing and keep the filter (typing=%v filter=%q)", m.typing, m.rowFilter)
	}
	if m = key(m, "esc"); m.rowFilter != "" {
		t.Errorf("esc left the filter as %q", m.rowFilter)
	}
}

// A filter belongs to the pane it was typed in. One filter shared between them
// would hide rows in the pane nobody is looking at.
func TestEachPaneKeepsItsOwnFilter(t *testing.T) {
	m := keys(testExploreModel(), "/", "seoul-b", "enter")
	if m.farmFilter != "seoul-b" || m.rowFilter != "" {
		t.Fatalf("farm filter %q / row filter %q", m.farmFilter, m.rowFilter)
	}
	if got := m.visibleFarms(); len(got) != 1 || got[0].Name != "seoul-b" {
		t.Fatalf("farm pane shows %d farms", len(got))
	}
}

// Enter on a row opens the same screen `vm show` prints, because it is that
// renderer. Esc puts the panes back.
func TestEnterOpensTheDetailAndEscCloses(t *testing.T) {
	m := keys(testExploreModel(), "tab", "enter")
	if len(m.detail) == 0 {
		t.Fatal("enter opened nothing")
	}
	body := strings.Join(m.detail, "\n")
	for _, want := range []string{"bastion", "u-1", "vctl ssh"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail does not carry %q:\n%s", want, body)
		}
	}
	if m = key(m, "esc"); len(m.detail) != 0 {
		t.Error("esc left the detail open")
	}
}

// An alternate screen takes everything back on exit, and the one thing on a VM
// detail worth keeping is the command that reaches it.
func TestLeavingFromADetailKeepsItForTheShell(t *testing.T) {
	m := keys(testExploreModel(), "tab", "enter", "p")
	if len(m.carry) == 0 {
		t.Fatal("p carried nothing out")
	}
	if !strings.Contains(strings.Join(m.carry, "\n"), "vctl ssh") {
		t.Error("what was carried out does not include the ssh line")
	}
}

// Enter on the left pane is "show me this one", not "open a detail" — there is
// no detail screen for a deployment here, `farm show` is that.
func TestEnterOnTheFarmPaneMovesToTheRows(t *testing.T) {
	m := key(testExploreModel(), "enter")
	if m.focus != paneRows {
		t.Error("enter on the deployments pane did not move to the rows")
	}
	if len(m.detail) != 0 {
		t.Error("enter on the deployments pane opened a detail")
	}
}

// The cursor has to stay on screen; a list that scrolls past its own selection
// is a list you cannot use past the first page.
func TestScrollingKeepsTheCursorVisible(t *testing.T) {
	m := testExploreModel()
	m.height = 8 // a short window: three or four rows
	m.focus = paneRows
	for i := 0; i < 5; i++ {
		m = key(m, "down")
	}
	if m.rowCur < m.rowTop || m.rowCur >= m.rowTop+m.rowsHeight() {
		t.Errorf("cursor %d is outside the window [%d,%d)", m.rowCur, m.rowTop, m.rowTop+m.rowsHeight())
	}
}

// A narrow terminal drops columns from the right rather than squeezing every
// column into something unreadable — and the heading still names what is left,
// so nothing vanishes without saying so.
func TestNarrowTerminalsDropColumnsInsteadOfSqueezingThem(t *testing.T) {
	wideT, wideW := vmColumns.layout(140)
	if len(wideT) != 5 {
		t.Fatalf("a wide pane shows %d columns, want all 5", len(wideT))
	}
	if wideW[0] < 20 {
		t.Errorf("the flexible column got %d columns of a 140-wide pane", wideW[0])
	}
	narrowT, narrowW := vmColumns.layout(50)
	if len(narrowT) >= 5 {
		t.Errorf("a 50-wide pane still claims %d columns", len(narrowT))
	}
	for i, w := range narrowW {
		if w < 6 {
			t.Errorf("column %q was squeezed to %d", narrowT[i], w)
		}
	}
	// Whatever survives is named.
	head := stripANSI(vmColumns.header(50))
	for _, title := range narrowT {
		if !strings.Contains(head, title) {
			t.Errorf("heading %q does not name the surviving column %q", head, title)
		}
	}
}

// The project answers "whose VM is this", which is what turns a list of names
// into one somebody can narrow.
func TestVMRowsCarryTheProject(t *testing.T) {
	m := testExploreModel()
	cols, cells := m.rowCells()
	if len(cells) == 0 {
		t.Fatal("no rows")
	}
	if got := stripANSI(cells[0][1]); got != "platform" {
		t.Errorf("second cell is %q, want the project", got)
	}
	line := stripANSI(cols.render(cells[0], 120))
	if i, j := strings.Index(line, "platform"), strings.Index(line, "ACTIVE"); i > j {
		t.Errorf("the project comes after the state; it narrows the list and should lead: %q", line)
	}
}

// The whole screen is as current as the title bar claims, so it has to claim
// something.
func TestTheTitleBarSaysHowOldTheReadingIs(t *testing.T) {
	m := testExploreModel()
	m.data.ReadAt = time.Now().Add(-3 * time.Minute)
	got := stripANSI(m.titleBar())
	for _, want := range []string{"2 deployments", "3 hosts", "3 VMs", "read 3m ago"} {
		if !strings.Contains(got, want) {
			t.Errorf("title %q does not carry %q", got, want)
		}
	}
}

// The store keeps VMs the control plane stopped listing so a farm's assessment
// can count them. A browser is not a count.
func TestExploreShowsOnlyTheVMsNovaStillLists(t *testing.T) {
	gone := time.Now().Add(-2 * time.Hour)
	got := liveInstances([]store.Instance{
		{InstanceID: "a", Name: "here"},
		{InstanceID: "b", Name: "deleted", MissingSince: &gone},
	})
	if len(got) != 1 || got[0].Name != "here" {
		t.Fatalf("got %v", names(got))
	}
}

// Explore is a listing, and listings are open to any authenticated user.
func TestExploreIsWiredUnderOpenstackAndUngated(t *testing.T) {
	root := NewRoot(Dependencies{})
	cmd, _, err := root.Find([]string{"openstack", "explore"})
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if got := cmd.Annotations["rbac.command"]; got != "" {
		t.Errorf("explore is gated as %q; it reads what the ungated listing reads", got)
	}
	if cmd.ValidArgsFunction == nil {
		t.Error("the deployment argument does not complete")
	}
	for _, alias := range []string{"browse", "ui"} {
		if _, _, err := root.Find([]string{"openstack", alias}); err != nil {
			t.Errorf("the %s alias does not resolve: %v", alias, err)
		}
	}
}

// The chooser is read by name. It led with a 24-wide endpoint, so a list whose
// purpose is recognising a deployment presented a column of IP addresses.
func TestFarmPickLabelsLeadWithTheName(t *testing.T) {
	labels := farmPickLabels([]farmChoice{
		{ID: "172.16.0.10:5000", Name: "incheon", Hosts: 7, Roles: "compute 7"},
		{ID: "192.168.201.90:5000", Hosts: 1, Roles: "controller 1"},
	})
	if !strings.HasPrefix(strings.TrimSpace(stripANSI(labels[0])), "incheon") {
		t.Errorf("named farm does not lead with its name: %q", stripANSI(labels[0]))
	}
	if !strings.Contains(labels[0], "172.16.0.10:5000") {
		t.Errorf("the endpoint is gone entirely: %q", stripANSI(labels[0]))
	}
	if !strings.HasPrefix(strings.TrimSpace(stripANSI(labels[1])), "192.168.201.90:5000") {
		t.Errorf("unnamed farm does not lead with its endpoint: %q", stripANSI(labels[1]))
	}
	if strings.Contains(stripANSI(labels[1]), "1 hosts") {
		t.Errorf("label says %q", stripANSI(labels[1]))
	}
}

func names(vms []store.Instance) []string {
	out := make([]string, 0, len(vms))
	for _, v := range vms {
		out = append(out, v.Name)
	}
	return out
}

// A reload keeps what the reader set up. Coming back to the deployments pane
// showing VMs unfiltered, after somebody had narrowed to one project on one
// farm, is a reload that costs more than it gives.
func TestReloadKeepsThePaneKindAndFilters(t *testing.T) {
	prev := testExploreModel()
	prev.focus, prev.kind = paneRows, kindHosts
	prev.farmFilter, prev.rowFilter = "seoul", "srv-000"
	prev.width, prev.height = 200, 60
	prev.rowCur, prev.farmCur = 5, 1

	next := newExploreModel(prev.data)
	next.adoptView(prev)

	if next.focus != paneRows || next.kind != kindHosts {
		t.Errorf("pane/kind = %v/%v", next.focus, next.kind)
	}
	if next.farmFilter != "seoul" || next.rowFilter != "srv-000" {
		t.Errorf("filters = %q / %q", next.farmFilter, next.rowFilter)
	}
	if next.width != 200 || next.height != 60 {
		t.Errorf("size = %dx%d", next.width, next.height)
	}
	// Not the cursor: row 5 of the old list is not row 5 of the new one.
	if next.rowCur != 0 {
		t.Errorf("the cursor was carried onto rows that may have changed: %d", next.rowCur)
	}
}

// r leaves the program so the caller can re-read; doing it inside Update would
// put a database call on the key path and freeze the screen with nothing on it
// to say why.
func TestReloadAsksTheCallerRatherThanQueryingInline(t *testing.T) {
	m := key(testExploreModel(), "r")
	if m.err != errExploreReload {
		t.Errorf("r produced err=%v, want the reload sentinel", m.err)
	}
}

// Every line has to fit the terminal. A row one column too wide wraps, and a
// wrapped row pushes the whole frame down until the layout is nonsense — the
// failure mode a full-screen program has that a printed listing does not.
func TestNoRenderedLineOverflowsTheTerminal(t *testing.T) {
	for _, size := range []struct{ w, h int }{{140, 40}, {100, 24}, {80, 20}, {60, 12}} {
		m := testExploreModel()
		m.width, m.height = size.w, size.h
		for _, view := range []string{"panes", "detail"} {
			if view == "detail" {
				m.focus = paneRows
				m.openDetail()
			}
			for i, line := range strings.Split(m.View(), "\n") {
				if w := lipgloss.Width(line); w > size.w {
					t.Errorf("%dx%d %s: line %d is %d columns wide: %q",
						size.w, size.h, view, i, w, stripANSI(line))
				}
			}
		}
	}
}

// The frame is both panes at once — that is the whole point of it, and a
// regression that drops one would still render something plausible.
func TestTheFrameShowsBothPanesAndTheKeys(t *testing.T) {
	got := stripANSI(testExploreModel().View())
	for _, want := range []string{
		"DEPLOYMENTS", "seoul-a", "seoul-b", // left
		"NAME", "PROJECT", "bastion", "platform", // right
		"tab pane", "q quit", // footer
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the frame does not carry %q:\n%s", want, got)
		}
	}
}

// A detail longer than the window scrolls, and says which part is on screen —
// otherwise the last line visible reads as the end of the record.
func TestALongDetailScrollsAndSaysWhereItIs(t *testing.T) {
	m := testExploreModel()
	m.focus = paneRows
	m.openDetail()
	m.height = 10 // shorter than the detail
	if len(m.detail) <= m.bodyHeight() {
		t.Skip("fixture detail is shorter than the window")
	}
	first := stripANSI(m.View())
	if !strings.Contains(first, "of "+itoaTest(len(m.detail))) {
		t.Errorf("no position indicator in a scrolled detail:\n%s", first)
	}
	m = key(m, "down")
	if m.detailTop != 1 {
		t.Errorf("down scrolled to %d", m.detailTop)
	}
	// And it stops at the end rather than scrolling into blank space.
	for i := 0; i < 200; i++ {
		m = key(m, "down")
	}
	if m.detailTop > len(m.detail)-m.bodyHeight() {
		t.Errorf("scrolled past the end: top=%d of %d lines", m.detailTop, len(m.detail))
	}
}

func itoaTest(n int) string {
	return strings.TrimSpace(strings.Replace(strings.Repeat(" ", 0)+fmtInt(n), "\n", "", -1))
}

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
