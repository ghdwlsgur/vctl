package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// assertReadsOnly walks a file and fails on any call that records something.
//
// Two commands now promise this in their help text — doctor and explore — and a
// promise the compiler does not check is a comment. Both are the commands
// somebody reaches for while a deployment is already misbehaving, which is
// exactly when nobody is thinking about what a "diagnostic" or a "browser"
// writes.
func assertReadsOnly(t *testing.T, filename, what string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	// Every store and cloud call that changes something. A read-only command
	// that grew one of these would still look read-only from the outside.
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
// It offered a Diagnose entry at first, which reached out to the farm's
// Keystone and Nova. That made a browser into something that authenticates
// against a control plane — a different kind of act from reading what was
// already collected, with different failure modes and a different reason to
// refuse. `farm doctor` is that command, and keeping the two apart is what lets
// this one promise it cannot make a farm's situation worse or slower.
func TestExploreNeverContactsAControlPlane(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "openstack_explore.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// diagnoseFarm authenticates and calls Nova; the api package is the client
	// itself. Either one reaching this file means the walk can now block on a
	// farm that is down.
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
				t.Errorf("explore calls openstackapi.%s at %s; it is meant to read what was "+
					"already collected", fn.Sel.Name, fset.Position(call.Pos()))
			}
		}
		return true
	})
}

// Without a terminal there is nobody to pick, and the useful thing to say is
// which commands answer the same questions without one.
//
// The check runs before the store is opened, so this needs no database — and it
// has to stay that way: a session that fails on a login prompt it could not
// have used is a worse error than the one it replaces.
func TestExploreRefusesWithoutATerminalAndNamesWhatToRunInstead(t *testing.T) {
	root := NewRoot(Dependencies{})
	cmd, _, err := root.Find([]string{"openstack", "explore"})
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	err = cmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("explore ran with no terminal to pick at")
	}
	for _, want := range []string{"farm list", "--farm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not mention %q: %v", want, err)
		}
	}
}

// The menu's count and the list behind it have to be the same set. A farm whose
// VMs have been deleted would otherwise offer "VMs (34)" and then list 25 —
// which reads as a broken listing rather than as VMs that are gone.
func TestExploreCountsOnlyTheVMsNovaStillLists(t *testing.T) {
	gone := time.Now().Add(-2 * time.Hour)
	got := liveInstances([]store.Instance{
		{InstanceID: "a", Name: "here"},
		{InstanceID: "b", Name: "deleted", MissingSince: &gone},
		{InstanceID: "c", Name: "also-here"},
	})
	if len(got) != 2 {
		t.Fatalf("got %d VMs, want the two that still exist", len(got))
	}
	for _, v := range got {
		if v.Name == "deleted" {
			t.Error("a VM the control plane no longer lists was offered to connect to")
		}
	}
}

// The headline carries the reconcile age because it is what makes every other
// number on it worth trusting — and "never" is a different statement from "a
// long time ago", not a bigger number.
func TestFarmHeadlineSaysWhenNothingHasEverReconciled(t *testing.T) {
	f := farmChoice{ID: "172.16.0.150:5000", Name: "seoul-b", Hosts: 5}
	snap := store.FarmSnapshot{Hosts: make([]store.OpenStackHost, 5)}
	vms := make([]store.Instance, 12)

	got := farmHeadline(f, snap, vms, time.Now())
	for _, want := range []string{"seoul-b", "172.16.0.150:5000", "5 hosts", "12 VMs", "never reconciled"} {
		if !strings.Contains(got, want) {
			t.Errorf("headline %q does not carry %q", got, want)
		}
	}

	at := time.Now().Add(-90 * time.Minute)
	snap.Run = &store.ReconcileRun{SucceededAt: &at}
	got = farmHeadline(f, snap, vms, time.Now())
	if strings.Contains(got, "never") {
		t.Errorf("headline still says never after a successful run: %q", got)
	}
	if !strings.Contains(got, "ago") {
		t.Errorf("headline %q does not say how long ago", got)
	}
}

// A picker row is read, not parsed. The name is what somebody recognises; the
// uuid identifies nothing to a reader and would cost 36 of the columns the
// address and hypervisor need.
func TestVMPickLabelLeadsWithTheNameAndLeavesOutTheUUID(t *testing.T) {
	v := store.Instance{
		InstanceID: "11111111-2222-3333-4444-555555555555",
		Name:       "bastion-01", Status: "ACTIVE", HypervisorHostname: "compute-03",
		ProjectID: "abc123", ProjectName: "platform",
		Addresses: []store.InstanceAddress{{Address: "192.168.201.55", Type: "floating"}},
	}
	got := vmPickLabel(v, nil)
	if !strings.HasPrefix(strings.TrimSpace(got), "bastion-01") {
		t.Errorf("label %q does not lead with the name", got)
	}
	if strings.Contains(got, v.InstanceID) {
		t.Errorf("label carries the uuid, which identifies nothing to a reader: %q", got)
	}
	// The project answers "whose VM is this", which is what turns a list of
	// names into a list somebody can narrow.
	for _, want := range []string{"platform", "192.168.201.55", "compute-03"} {
		if !strings.Contains(got, want) {
			t.Errorf("label %q does not carry %q", got, want)
		}
	}
	if i, j := strings.Index(stripANSI(got), "platform"), strings.Index(stripANSI(got), "ACTIVE"); i > j {
		t.Errorf("the project comes after the state; it narrows the list and should lead: %q", stripANSI(got))
	}
}

// A project nothing has named still has an id, and that is the only handle it
// has. Collections predating the project_name column leave it empty.
func TestVMPickLabelFallsBackToTheProjectID(t *testing.T) {
	v := store.Instance{InstanceID: "abc", Name: "vm-1", ProjectID: "4b854e2819e44b53"}
	if got := vmPickLabel(v, nil); !strings.Contains(got, "4b85") {
		t.Errorf("an unnamed project left the row with nothing to say whose it is: %q", got)
	}
}

// A VM with no name still has to be pickable — the uuid is the only handle it
// has, so that is the one case where it belongs in the row.
func TestVMPickLabelFallsBackToTheUUIDForAnUnnamedVM(t *testing.T) {
	v := store.Instance{InstanceID: "11111111-2222-3333-4444-555555555555", Status: "ACTIVE"}
	if got := vmPickLabel(v, nil); !strings.Contains(got, "11111111") {
		t.Errorf("an unnamed VM has nothing to pick by: %q", got)
	}
}

// Explore is a listing, and listings are open to any authenticated user. A
// picker over data `vctl openstack` already prints must not need a grant that
// `vctl openstack` does not.
func TestExploreIsWiredUnderOpenstackAndUngated(t *testing.T) {
	root := NewRoot(Dependencies{})
	cmd, _, err := root.Find([]string{"openstack", "explore"})
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if cmd.Name() != "explore" {
		t.Fatalf("found %q", cmd.Name())
	}
	if got := cmd.Annotations["rbac.command"]; got != "" {
		t.Errorf("explore is gated as %q; it reads what the ungated listing reads", got)
	}
	if cmd.ValidArgsFunction == nil {
		t.Error("the deployment argument does not complete")
	}
	// browse, because that is the other word people reach for.
	if _, _, err := root.Find([]string{"openstack", "browse"}); err != nil {
		t.Errorf("the browse alias does not resolve: %v", err)
	}
}

// The chooser is read by name. It led with a 24-wide endpoint, so a list whose
// purpose is recognising a deployment presented a column of IP addresses with
// the names pushed off to the right — which is what naming a farm was supposed
// to fix.
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
	// An unnamed deployment has nothing else to lead with.
	if !strings.HasPrefix(strings.TrimSpace(stripANSI(labels[1])), "192.168.201.90:5000") {
		t.Errorf("unnamed farm does not lead with its endpoint: %q", stripANSI(labels[1]))
	}
	// "1 hosts" is the sort of thing a reader stops on.
	if strings.Contains(stripANSI(labels[1]), "1 hosts") {
		t.Errorf("label says %q", stripANSI(labels[1]))
	}
}
