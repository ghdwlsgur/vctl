package cli

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
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
	for _, want := range []string{"openstack list", "--farm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}

// Browsing is the default human path. The old tabular listing remains an
// explicit subcommand for scripts and for terminals that cannot run a TUI.
func TestBareOpenStackBrowsesAndListPreservesTheTable(t *testing.T) {
	root := NewRoot(Dependencies{})
	openstack, _, err := root.Find([]string{"openstack"})
	if err != nil {
		t.Fatalf("find openstack: %v", err)
	}
	if err := openstack.Args(openstack, []string{"seoul"}); err != nil {
		t.Fatalf("bare openstack does not accept a starting farm: %v", err)
	}
	if err := openstack.RunE(openstack, []string{"seoul"}); err == nil || !strings.Contains(err.Error(), "full-screen browser") {
		t.Fatalf("bare openstack did not enter the browser path: %v", err)
	}

	list, _, err := root.Find([]string{"openstack", "list"})
	if err != nil {
		t.Fatalf("the old table has no list command: %v", err)
	}
	for _, flag := range []string{"farm", "role", "wide", "json", "all", "parked"} {
		if list.Flags().Lookup(flag) == nil {
			t.Errorf("openstack list lost --%s", flag)
		}
	}
}

func TestLegacyBareListingFlagsStillChooseTheTable(t *testing.T) {
	for _, flags := range [][]string{
		{"--farm", "seoul"}, {"--role", "compute"}, {"--wide"},
		{"--json"}, {"--all"}, {"--parked"}, {"--fresh", "--json"},
	} {
		t.Run(strings.Join(flags, "_"), func(t *testing.T) {
			called := false
			root := NewRoot(Dependencies{NewApp: func() (*app.App, error) {
				called = true
				return nil, errors.New("listing sentinel")
			}})
			cmd, _, err := root.Find([]string{"openstack"})
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.ParseFlags(flags); err != nil {
				t.Fatalf("parse %v: %v", flags, err)
			}
			if err := cmd.RunE(cmd, nil); err == nil || err.Error() != "listing sentinel" {
				t.Fatalf("%v did not take the listing path: %v", flags, err)
			}
			if !called {
				t.Fatalf("%v entered the terminal browser instead of the listing", flags)
			}
		})
	}
}

// testExploreModel is two deployments with something in each, sized like a
// normal terminal.
func testExploreModel() exploreModel {
	at := time.Now().Add(-20 * time.Minute)
	d := exploreData{
		Farms: []farmChoice{
			farmOf("10.0.0.1:5000", "seoul-a", "compute", "controller"),
			farmOf("10.0.0.2:5000", "seoul-b", "compute"),
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
	head := ui.StripANSI(vmColumns.header(50))
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
	if got := ui.StripANSI(cells[0][1]); got != "platform" {
		t.Errorf("second cell is %q, want the project", got)
	}
	line := ui.StripANSI(cols.render(cells[0], 120))
	if i, j := strings.Index(line, "platform"), strings.Index(line, "ACTIVE"); i > j {
		t.Errorf("the project comes after the state; it narrows the list and should lead: %q", line)
	}
}

// The whole screen is as current as the title bar claims, so it has to claim
// something.
func TestTheTitleBarSaysHowOldTheReadingIs(t *testing.T) {
	m := testExploreModel()
	m.data.ReadAt = time.Now().Add(-3 * time.Minute)
	got := ui.StripANSI(m.titleBar())
	for _, want := range []string{"OPENSTACK", "2 farms", "3 hosts", "3 VMs", "read 3m ago"} {
		if !strings.Contains(got, want) {
			t.Errorf("title %q does not carry %q", got, want)
		}
	}
}

func TestAFreshReadingSaysJustNow(t *testing.T) {
	m := testExploreModel()
	got := ui.StripANSI(m.titleBar())
	if !strings.Contains(got, "just now") || strings.Contains(got, "0s ago") {
		t.Fatalf("fresh title = %q", got)
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
		farmOf("172.16.0.10:5000", "incheon", "compute", "compute"),
		farmOf("192.168.201.90:5000", "", "controller"),
	})
	if !strings.HasPrefix(strings.TrimSpace(ui.StripANSI(labels[0])), "incheon") {
		t.Errorf("named farm does not lead with its name: %q", ui.StripANSI(labels[0]))
	}
	if !strings.Contains(labels[0], "172.16.0.10:5000") {
		t.Errorf("the endpoint is gone entirely: %q", ui.StripANSI(labels[0]))
	}
	if !strings.HasPrefix(strings.TrimSpace(ui.StripANSI(labels[1])), "192.168.201.90:5000") {
		t.Errorf("unnamed farm does not lead with its endpoint: %q", ui.StripANSI(labels[1]))
	}
	if strings.Contains(ui.StripANSI(labels[1]), "1 hosts") {
		t.Errorf("label says %q", ui.StripANSI(labels[1]))
	}
}

func names(vms []store.Instance) []string {
	out := make([]string, 0, len(vms))
	for _, v := range vms {
		out = append(out, v.Name)
	}
	return out
}

// A refresh keeps what the reader set up. It used to leave and re-enter the
// program to re-read, which meant rebuilding the model and carrying the panes,
// the filters and the size across by hand; refreshing in place keeps them
// because nothing takes them away.
func TestRefreshingKeepsThePaneKindAndFilters(t *testing.T) {
	m := testExploreModel()
	m.focus, m.kind = paneRows, kindHosts
	m.farmFilter, m.rowFilter = "seoul", "srv-000"
	m.width, m.height = 200, 60

	m = m.onRefreshed(exploreRefreshed{data: testExploreModel().data})

	if m.focus != paneRows || m.kind != kindHosts {
		t.Errorf("pane/kind = %v/%v", m.focus, m.kind)
	}
	if m.farmFilter != "seoul" || m.rowFilter != "srv-000" {
		t.Errorf("filters = %q / %q", m.farmFilter, m.rowFilter)
	}
	if m.width != 200 || m.height != 60 {
		t.Errorf("size = %dx%d", m.width, m.height)
	}
}

// The cursor comes back onto the same machine, not the same row number.
//
// Rows move between readings — a VM is created, another is deleted — so putting
// the cursor back on position 1 hands somebody a different machine than the one
// they were looking at, in a browser whose next keypress may be enter.
func TestRefreshingPutsTheCursorBackOnTheSameMachine(t *testing.T) {
	m := testExploreModel()
	m.focus = paneRows
	m = key(m, "down") // the second VM: quay-registry
	if got := m.selection().row; got != "u-2" {
		t.Fatalf("cursor is on %q before the refresh", got)
	}

	// The same fleet with one more VM, sorted ahead of the one under the cursor.
	next := testExploreModel().data
	next.VMs["10.0.0.1:5000"] = append([]store.Instance{{
		DeploymentID: "10.0.0.1:5000", InstanceID: "u-0", Name: "argocd", Status: "ACTIVE",
		ProjectName: "platform", HypervisorHostname: "sre-srv-0001",
	}}, next.VMs["10.0.0.1:5000"]...)

	m = m.onRefreshed(exploreRefreshed{data: next})

	if got := m.selection().row; got != "u-2" {
		t.Errorf("after a refresh the cursor is on %q, want the machine it was on", got)
	}
	if m.rowCur != 2 {
		t.Errorf("cursor at row %d; the new VM was inserted above it", m.rowCur)
	}
}

// A machine that is gone takes the cursor to the top rather than to whatever
// row inherited its number.
func TestARefreshedRowThatIsGoneDoesNotHandOverItsPosition(t *testing.T) {
	m := testExploreModel()
	m.focus = paneRows
	m = key(m, "down")

	next := testExploreModel().data
	next.VMs["10.0.0.1:5000"] = next.VMs["10.0.0.1:5000"][:1] // quay-registry is gone
	m = m.onRefreshed(exploreRefreshed{data: next})

	if m.rowCur != 0 {
		t.Errorf("cursor at row %d after the row it was on disappeared", m.rowCur)
	}
}

// r reads in the background. Reading inside Update would stop the whole screen
// for as long as the database takes, with nothing on it to say why — the reason
// this used to leave the program to re-read at all.
func TestRefreshingHappensOffTheKeyPath(t *testing.T) {
	m := testExploreModel()
	m.refresh = func() (exploreData, error) {
		t.Error("the refresh ran on the key path")
		return exploreData{}, nil
	}
	out, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	m = out.(exploreModel)
	if !m.refreshing {
		t.Error("r did not start a refresh")
	}
	if cmd == nil {
		t.Fatal("r produced no command, so nothing will read")
	}
	if m.err != nil {
		t.Errorf("r ended the program: %v", m.err)
	}
	// A second r while one is in flight is not a second read.
	before := m
	out, cmd = before.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if cmd != nil {
		t.Error("r during a refresh started another one")
	}
	_ = out
}

// A stored reading says so, and stops saying so once the real one lands. The
// two are the same rows and cannot be told apart by looking at them.
func TestAStoredReadingSaysItIsStoredUntilTheRefreshLands(t *testing.T) {
	m := testExploreModel()
	m.data.Cached = true
	m.data.ReadAt = time.Now().Add(-4 * time.Minute)
	m.refreshing = true

	got := ui.StripANSI(m.titleBar())
	for _, want := range []string{"cached", "4m old", "reading…"} {
		if !strings.Contains(got, want) {
			t.Errorf("title %q does not carry %q", got, want)
		}
	}

	fresh := testExploreModel().data
	fresh.ReadAt = time.Now()
	got = ui.StripANSI(m.onRefreshed(exploreRefreshed{data: fresh}).titleBar())
	if strings.Contains(got, "cached") || strings.Contains(got, "reading…") {
		t.Errorf("title still claims a stored reading after a live one landed: %q", got)
	}
}

// A refresh that fails leaves what is on screen alone and says what happened.
// Exiting would lose the reader's place over something they did not ask for,
// and the rows already up are still worth reading.
func TestARefreshThatFailsKeepsWhatIsOnScreen(t *testing.T) {
	m := testExploreModel()
	m.data.Cached = true
	before := len(m.data.Farms)

	m = m.onRefreshed(exploreRefreshed{err: errors.New("dial tcp 192.168.201.12:5432: timeout")})

	if len(m.data.Farms) != before {
		t.Errorf("a failed refresh emptied the screen: %d farms", len(m.data.Farms))
	}
	if m.refreshing {
		t.Error("still marked as reading after the read came back")
	}
	if got := ui.StripANSI(m.titleBar()); !strings.Contains(got, "refresh failed") ||
		!strings.Contains(got, "timeout") {
		t.Errorf("title does not report the failure: %q", got)
	}
	if !m.data.Cached {
		t.Error("the screen stopped calling itself cached without a live reading")
	}
}

// The browser opens on the stored reading and does not go to the database to do
// it. Opening the store first costs a Vault credential and a TLS handshake —
// measured at ten seconds on a bad path — behind an alternate screen that shows
// nothing for the whole of it.
func TestExploreOpensFromTheStoredReadingWithoutADatabase(t *testing.T) {
	dir := t.TempDir()
	// A DSN nothing is listening on: reaching the database at all fails this.
	a := &app.App{Cfg: &config.Config{
		StateDir:   dir,
		LocalDBDSN: "postgres://nobody@127.0.0.1:1/none?sslmode=disable",
	}}
	snap := store.Fleet{
		Deployments: []store.Deployment{{ID: "10.0.0.1:5000", DisplayName: "seoul-a"}},
		Hosts: []store.OpenStackHost{
			{Hostname: "sre-srv-0001", Farm: "10.0.0.1:5000", Detected: true, Roles: []string{"compute"}},
		},
		Instances: []store.Instance{
			{DeploymentID: "10.0.0.1:5000", InstanceID: "u-1", Name: "bastion", Status: "ACTIVE"},
		},
		ReadAt: time.Now().Add(-90 * time.Second),
	}
	if err := a.FleetCache().Save(fleet.ShapeVMs, snap); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := firstExploreScreen(context.Background(), a, &openLater{app: a}, false)
	if err != nil {
		t.Fatalf("first screen: %v", err)
	}
	if !got.Cached {
		t.Error("the screen does not know it came off disk")
	}
	if len(got.Farms) != 1 || got.Farms[0].Name != "seoul-a" {
		t.Fatalf("farms = %v", got.Farms)
	}
	if len(got.VMs["10.0.0.1:5000"]) != 1 {
		t.Errorf("the stored VMs did not survive: %v", got.VMs)
	}
	if !got.ReadAt.Equal(snap.ReadAt) {
		t.Errorf("age is measured from %s, not from when the database was read", got.ReadAt)
	}
}

// The store is opened when something needs it, not before the screen.
//
// Wrapping the command in withStore is what made the browser pay for a Vault
// credential before deciding whether it needed one, and it is a one-word change
// to put back.
func TestExploreDoesNotOpenTheStoreBeforeTheScreen(t *testing.T) {
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
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "withStore" {
			return true
		}
		t.Errorf("explore opens the store at %s; it opens it when a read needs it — see openLater",
			fset.Position(call.Pos()))
		return true
	})
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
						size.w, size.h, view, i, w, ui.StripANSI(line))
				}
			}
		}
	}
}

// The frame is both panes at once — that is the whole point of it, and a
// regression that drops one would still render something plausible.
func TestTheFrameShowsBothPanesAndTheKeys(t *testing.T) {
	got := ui.StripANSI(testExploreModel().View())
	for _, want := range []string{
		"FARMS", "seoul-a", "2H 2V", "seoul-b", "1H 1V", // left
		"NAME", "PROJECT", "bastion", "platform", // right
		"tab switch", "q quit", // footer
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the frame does not carry %q:\n%s", want, got)
		}
	}
}

func TestTheSummaryHasBreathingRoomBeforeTheBrowserPanes(t *testing.T) {
	lines := strings.Split(ui.StripANSI(testExploreModel().View()), "\n")
	if len(lines) < 3 || lines[1] != "" || !strings.Contains(lines[2], "FARMS") {
		t.Fatalf("expected summary, blank line, then panes; first lines are %q", lines[:min(3, len(lines))])
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
	first := ui.StripANSI(m.View())
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

// The renderer draws the model and never edits it.
//
// This is what splitting openstack_explore.go into a model file and a view file
// is for. Filing the functions apart is a filing decision and nothing enforces
// it; a value receiver is enforced by the compiler at every call site, and it is
// the difference between a renderer and a second place the selection can change.
//
// The view does call clampIndex, to find which row is the current one. Clamping
// to read is not clamping to store — the trap a pointer receiver would open is
// a layout pass that corrects an out-of-range cursor as a side effect of drawing
// it, so a window resize would move the selection under the cursor.
func TestTheRendererCannotMoveTheCursor(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "openstack_explore_view.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var checked int
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
			continue
		}
		checked++
		if _, isPtr := fn.Recv.List[0].Type.(*ast.StarExpr); isPtr {
			t.Errorf("%s takes its model by pointer at %s; the renderer may read the model, not move it",
				fn.Name.Name, fset.Position(fn.Pos()))
		}
	}
	// A guard over nothing passes. If the methods move again this says so
	// instead of going quietly green.
	if checked < 10 {
		t.Errorf("only %d methods found in the view; this test is not reading the file it names", checked)
	}
}
