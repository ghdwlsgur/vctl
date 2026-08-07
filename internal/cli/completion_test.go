package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// value returns what a completion would put on the command line, dropping the
// description the shell only displays.
func value(candidate string) string {
	v, _, _ := strings.Cut(candidate, "\t")
	return v
}

func values(candidates []string) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, value(c))
	}
	return out
}

func TestFarmCompletionLeadsWithTheNameAndFallsBackToTheEndpoint(t *testing.T) {
	seoulB := farmOf("172.16.0.245:5000", "seoul-b", "compute", "compute", "compute")
	seoulB.State = store.StateMaintenance
	farms := []farmChoice{
		farmOf("172.16.0.21:5000", "seoul-a", "compute", "compute", "compute", "compute", "compute", "compute", "compute"),
		seoulB,
		farmOf("10.10.0.9:5000", "", "compute", "compute"),
	}

	t.Run("nothing typed offers the names", func(t *testing.T) {
		got := values(farmCompletions(farms, nil, ""))
		want := []string{"seoul-a", "seoul-b", "10.10.0.9:5000"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})

	t.Run("an address typed offers the endpoint", func(t *testing.T) {
		// The whole point of the fallback: 172. matches no display name, and
		// without it the person typing an endpoint gets nothing.
		got := values(farmCompletions(farms, nil, "172."))
		if len(got) != 2 || got[0] != "172.16.0.21:5000" {
			t.Fatalf("got %v, want the two endpoints", got)
		}
	})

	t.Run("the description carries what the value does not", func(t *testing.T) {
		got := farmCompletions(farms, nil, "seoul-b")
		if len(got) != 1 {
			t.Fatalf("got %d candidates, want 1: %v", len(got), got)
		}
		for _, want := range []string{"172.16.0.245:5000", "3 hosts", store.StateMaintenance} {
			if !strings.Contains(got[0], want) {
				t.Errorf("description %q does not mention %q", got[0], want)
			}
		}
	})

	t.Run("extra words are offered too", func(t *testing.T) {
		got := values(farmCompletions(farms, []string{unassignedFarm}, "unas"))
		if len(got) != 1 || got[0] != unassignedFarm {
			t.Fatalf("got %v, want [unassigned]", got)
		}
	})
}

func TestRoleCompletionCountsCurrentRolesOnly(t *testing.T) {
	hosts := []store.OpenStackHost{
		{Hostname: "a", Roles: []string{"controller", "compute"}},
		{Hostname: "b", Roles: []string{"compute"}},
		// A role this host has stopped holding. --role compute has to mean a
		// machine running nova now, and the completion has to agree with it.
		{Hostname: "c", Dropped: []store.DroppedRole{{Role: "network"}}},
	}
	got := roleCompletions(hosts, "")
	if v := values(got); len(v) != 2 || v[0] != "compute" || v[1] != "controller" {
		t.Fatalf("got %v, want [compute controller]", v)
	}
	if !strings.Contains(got[0], "2 hosts") {
		t.Errorf("compute should be described as 2 hosts, got %q", got[0])
	}
	if len(roleCompletions(hosts, "net")) != 0 {
		t.Error("a dropped role was offered")
	}
}

func TestProjectCompletionOffersANameOnceAcrossFarms(t *testing.T) {
	projects := []store.Project{
		{DeploymentID: "farm-a", ID: "aaa", Name: "admin", VMs: 4},
		{DeploymentID: "farm-b", ID: "bbb", Name: "admin", VMs: 6},
		{DeploymentID: "farm-a", ID: "ccc", Name: "platform", VMs: 2},
		{DeploymentID: "farm-b", ID: "ddd", VMs: 1},
	}
	farms := map[string]string{"farm-a": "seoul-a", "farm-b": "seoul-b"}

	got := projectCompletions(projects, farms, "")
	// admin exists in both farms as two different projects. Offering it twice
	// would look like a duplicate entry, not like two projects.
	var admins int
	for _, c := range got {
		if value(c) == "admin" {
			admins++
			if !strings.Contains(c, "2 farms") {
				t.Errorf("admin should say it spans 2 farms, got %q", c)
			}
		}
	}
	if admins != 1 {
		t.Errorf("admin offered %d times, want once", admins)
	}
	// A project nothing has named is still selectable, by the only handle it
	// has.
	if !contains(values(got), "ddd") {
		t.Errorf("the unnamed project was not offered: %v", values(got))
	}
	if !contains(values(projectCompletions(projects, farms, "cc")), "ccc") {
		t.Error("typing an id prefix did not offer the id")
	}
}

func TestVMCompletionCompletesToTheIDAndReadsAsTheName(t *testing.T) {
	vms := []store.Instance{
		{DeploymentID: "farm-a", InstanceID: "11111111-2222-3333-4444-555555555555", Name: "bastion", Status: "ACTIVE"},
		{DeploymentID: "farm-b", InstanceID: "99999999-8888-7777-6666-555555555555", Status: "SHUTOFF"},
	}
	farms := map[string]string{"farm-a": "seoul-a", "farm-b": "seoul-b"}

	got := vmCompletions(vms, farms, "")
	if len(got) != 2 {
		t.Fatalf("got %d candidates, want 2", len(got))
	}
	// The value is the identity, because that is what --vm accepts. The name is
	// only how a person finds it in the menu.
	if value(got[0]) != vms[0].InstanceID {
		t.Errorf("completed to %q, want the uuid", value(got[0]))
	}
	if !strings.Contains(got[0], "bastion") || !strings.Contains(got[0], "seoul-a") {
		t.Errorf("description does not identify the VM: %q", got[0])
	}
	if !strings.Contains(got[1], "SHUTOFF") {
		t.Errorf("a stopped VM should say so: %q", got[1])
	}

	// A providerID is what gets pasted out of kubectl, and the line already
	// carrying that prefix still has to complete.
	pasted := vmCompletions(vms, farms, providerIDPrefix+"1111")
	if len(pasted) != 1 || value(pasted[0]) != vms[0].InstanceID {
		t.Fatalf("providerID prefix did not complete: %v", pasted)
	}
}

func TestVMNameCompletionSaysWhenANameFitsMoreThanOneVM(t *testing.T) {
	vms := []store.Instance{
		{DeploymentID: "farm-a", InstanceID: "a", Name: "bastion"},
		{DeploymentID: "farm-b", InstanceID: "b", Name: "bastion"},
		{DeploymentID: "farm-a", InstanceID: "c", Name: "registry"},
		{DeploymentID: "farm-a", InstanceID: "d"},
	}
	got := vmNameCompletions(vms, map[string]string{"farm-a": "seoul-a"}, "")
	if v := values(got); len(v) != 2 {
		t.Fatalf("got %v, want bastion and registry once each", v)
	}
	if !strings.Contains(got[0], "2 farms") {
		t.Errorf("a name in two farms is two machines and should say so: %q", got[0])
	}
	// A VM with no name has nothing to search for; it is reachable by uuid.
	if contains(values(got), "") {
		t.Error("an empty name was offered")
	}
}

func TestInventoryHostCompletionLeavesOutRetiredHosts(t *testing.T) {
	servers := []store.Server{
		{Hostname: "sre-svr-0001", DC: "seoul"},
		{Hostname: "sre-svr-0002", DC: "seoul", State: store.StateMaintenance},
		{Hostname: "sre-svr-0003", DC: "seoul", State: store.StateRetired},
	}
	got := inventoryHostCompletions(servers, "sre-")
	if v := values(got); len(v) != 2 {
		t.Fatalf("got %v, want the two hosts that are not retired", v)
	}
	if !strings.Contains(got[1], store.StateMaintenance) {
		t.Errorf("a host in maintenance should say so: %q", got[1])
	}
}

// A description is display text and the value is a protocol field. cobra splits
// them on a tab and the shell splits candidates on newlines, so a VM named with
// either — nova accepts both — would move the boundary.
func TestCandidateFlattensWhatWouldBreakTheProtocol(t *testing.T) {
	got := candidate("id", "na\tme\nfarm")
	if strings.Count(got, "\t") != 1 {
		t.Errorf("description tab survived: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("description newline survived: %q", got)
	}
	if value(got) != "id" {
		t.Errorf("value became %q", value(got))
	}
	if candidate("id", "") != "id" {
		t.Errorf("an empty description should leave no separator, got %q", candidate("id", ""))
	}
}

func TestByPositionAsksADifferentQuestionPerArgument(t *testing.T) {
	first := staticCompletions("farm-a")
	second := staticCompletions("active", "retired")
	fn := byPosition(first, second)

	got, _ := fn(nil, nil, "")
	if len(got) != 1 || got[0] != "farm-a" {
		t.Fatalf("first argument got %v", got)
	}
	got, _ = fn(nil, []string{"farm-a"}, "")
	if len(got) != 2 {
		t.Fatalf("second argument got %v, want the states", got)
	}
	// Past the end there is no question left to answer.
	if got, _ = fn(nil, []string{"farm-a", "active"}, ""); len(got) != 0 {
		t.Fatalf("third argument got %v, want nothing", got)
	}
}

// fleetValueFlags are the flags whose values are things the fleet knows about,
// rather than free text. Every one of them has to complete.
//
// A list of names rather than a list of (command, flag) pairs, so a command
// that gains a --farm next year is covered by this test on the day it is
// written instead of the day somebody remembers to add it here.
var fleetValueFlags = map[string]bool{
	"farm": true, "host": true, "hostname": true,
	"project": true, "role": true, "server": true, "vm": true,
}

// notFleetValues are the flags that carry one of those words and do not mean
// it. Each is a decision recorded here rather than a hole in the rule, and
// adding to this map should take an argument.
var notFleetValues = map[string]string{
	"vctl add --host":       "the name being registered — by definition not in the inventory yet",
	"vctl ip set --farm":    "a label (A/B/C/D) on an address record, not a deployment",
	"vctl ip set --project": "a free-text purpose on an address record, not a Keystone project",
}

func TestEveryFleetValueFlagCompletes(t *testing.T) {
	root := NewRoot(Dependencies{})
	var walk func(cmd *cobra.Command, path string)
	walk = func(cmd *cobra.Command, path string) {
		for name := range fleetValueFlags {
			if cmd.LocalFlags().Lookup(name) == nil || notFleetValues[path+" --"+name] != "" {
				continue
			}
			if _, ok := cmd.GetFlagCompletionFunc(name); !ok {
				t.Errorf("%s --%s has no completion; it names something the inventory knows, "+
					"so registerCompletion belongs beside the flag "+
					"(or say why not in notFleetValues)", path, name)
			}
		}
		for _, sub := range cmd.Commands() {
			// Hidden commands are run by the host-side stamper and the agents,
			// never typed, so there is no keystroke here to complete.
			if !sub.IsAvailableCommand() {
				continue
			}
			walk(sub, path+" "+sub.Name())
		}
	}
	walk(root, "vctl")
}

// The command tree is built once per process here and completions are
// registered against pflag.Flag pointers, so a second tree must not lose them.
// It did not, but the failure mode — completions that work in the first tree
// and silently not in the second — is invisible without asking.
func TestCompletionsSurviveASecondCommandTree(t *testing.T) {
	_ = NewRoot(Dependencies{})
	second := NewRoot(Dependencies{})
	vm, _, err := second.Find([]string{"openstack", "vm"})
	if err != nil {
		t.Fatalf("find openstack vm: %v", err)
	}
	if _, ok := vm.GetFlagCompletionFunc("farm"); !ok {
		t.Error("the second tree's 'openstack vm --farm' has no completion")
	}
	if vm.ValidArgsFunction == nil {
		t.Error("the second tree's 'openstack vm' has no argument completion")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
