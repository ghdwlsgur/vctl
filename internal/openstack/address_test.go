package openstack

import (
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func addrs(specs ...[2]string) []store.InstanceAddress {
	out := make([]store.InstanceAddress, 0, len(specs))
	for _, s := range specs {
		out = append(out, store.InstanceAddress{Address: s[0], Type: s[1]})
	}
	return out
}

// A VM answers on several addresses and they are not interchangeable. Nothing
// in the data marks them apart, so taking whichever nova listed first was right
// by accident — and most of them are tenant networks a workstation cannot reach.
func TestReachableAddressRanksWhatCanBeReached(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []store.InstanceAddress
		nets []string
		want string
	}{
		{
			// Somebody attached it for exactly this reason. It outranks a guess
			// made from a prefix.
			name: "floating beats the operator network",
			in:   addrs([2]string{"192.168.10.5", "fixed"}, [2]string{"203.0.113.9", "floating"}),
			nets: []string{"192.168."},
			want: "203.0.113.9",
		},
		{
			name: "operator network beats a tenant one",
			in:   addrs([2]string{"10.3.1.7", "fixed"}, [2]string{"192.168.201.207", "fixed"}),
			nets: []string{"192.168."},
			want: "192.168.201.207",
		},
		{
			// No operator network configured is not a reason to answer nothing.
			// An address somebody can try beats a blank column.
			name: "an unranked address is still an answer",
			in:   addrs([2]string{"10.3.1.7", "fixed"}),
			nets: nil,
			want: "10.3.1.7",
		},
		{
			// Real state: a VM that is building, or one whose port was detached.
			name: "no addresses is empty, not a guess",
			in:   nil,
			nets: []string{"192.168."},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PreferredAddress(tc.in, tc.nets); got != tc.want {
				t.Errorf("PreferredAddress = %q, want %q", got, tc.want)
			}
		})
	}
}

// The returned value has to be an address and nothing else. It used to come
// back decorated — "192.168.10.5 (+2)" with terminal styling — because the only
// caller was a table cell. Anything that wants to connect to it needs the
// address alone, and that is why this is separate from the rendering.
func TestReachableAddressReturnsAnAddressNotACell(t *testing.T) {
	got := PreferredAddress(addrs(
		[2]string{"192.168.10.5", "fixed"},
		[2]string{"10.3.1.7", "fixed"},
		[2]string{"10.4.1.7", "fixed"},
	), []string{"192.168."})

	if got != "192.168.10.5" {
		t.Errorf("PreferredAddress = %q, want the bare address", got)
	}
}

func TestOnOperatorNetworkMatchesByPrefix(t *testing.T) {
	if !OnOperatorNetwork("192.168.10.5", []string{"10.0.", "192.168."}) {
		t.Error("an operator-network address was not recognised")
	}
	if OnOperatorNetwork("10.3.1.7", []string{"192.168."}) {
		t.Error("a tenant address was taken for an operator one")
	}
	// An empty prefix would match everything, which turns a blank config line
	// into "every address is reachable".
	if OnOperatorNetwork("10.3.1.7", []string{""}) {
		t.Error("an empty prefix matched")
	}
}

// A listing shows what it knows; a connection is a claim about which machine
// answers. Tenant ranges repeat across deployments — two farms both holding
// 10.3.1.7 is the normal case — so the only addresses worth connecting to are
// the ones that say something about reachability.
func TestConnectableAddressRefusesWhatItCannotVouchFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []store.InstanceAddress
		nets []string
		want string
	}{
		{
			name: "floating is what somebody attached to be reached",
			in:   addrs([2]string{"10.3.1.7", "fixed"}, [2]string{"203.0.113.9", "floating"}),
			nets: []string{"192.168."},
			want: "203.0.113.9",
		},
		{
			name: "an operator network is one this fleet routes",
			in:   addrs([2]string{"10.3.1.7", "fixed"}, [2]string{"192.168.201.207", "fixed"}),
			nets: []string{"192.168."},
			want: "192.168.201.207",
		},
		{
			// The listing answers 10.3.1.7 here, and should. Connecting to it
			// would be a guess about whose 10.3.1.7 it is.
			name: "a tenant address alone is not an answer",
			in:   addrs([2]string{"10.3.1.7", "fixed"}),
			nets: []string{"192.168."},
			want: "",
		},
		{
			// No operator networks configured means nothing is known to route,
			// so nothing is vouched for.
			name: "no operator network configured vouches for nothing",
			in:   addrs([2]string{"10.3.1.7", "fixed"}),
			nets: nil,
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ConnectableAddress(tc.in, tc.nets); got != tc.want {
				t.Errorf("ConnectableAddress = %q, want %q", got, tc.want)
			}
		})
	}
}

// The two policies differ exactly where it matters: the listing still answers
// for a tenant-only VM, and the connection does not.
func TestTheListingAnswersWhereTheConnectionRefuses(t *testing.T) {
	only := addrs([2]string{"10.3.1.7", "fixed"})
	if got := PreferredAddress(only, []string{"192.168."}); got == "" {
		t.Error("the listing dropped the only address it had; a blank column is worse than a tenant one")
	}
	if got := ConnectableAddress(only, []string{"192.168."}); got != "" {
		t.Errorf("ConnectableAddress = %q, want nothing to connect to", got)
	}
}

func jumpTarget() store.Instance {
	return store.Instance{
		InstanceID: "t-1", ProjectID: "p-1", Name: "worker-1", Status: "ACTIVE",
		Addresses: []store.InstanceAddress{
			{NetworkName: "tenant-a", Address: "10.3.3.17"},
		},
	}
}

func jumpSibling(id, name, project string, addrs ...store.InstanceAddress) store.Instance {
	return store.Instance{InstanceID: id, ProjectID: project, Name: name, Status: "ACTIVE", Addresses: addrs}
}

// A sibling holding a port on the target's tenant network and a floating
// address is the hop; the tenant door is the target's own address on that
// network.
func TestTenantJumpFindsTheFloatingSiblingOnTheSharedNetwork(t *testing.T) {
	via, viaAddr, door, ok := TenantJump(jumpTarget(), []store.Instance{
		jumpSibling("s-1", "worker-2", "p-1",
			store.InstanceAddress{NetworkName: "tenant-a", Address: "10.3.3.18"},
			store.InstanceAddress{Address: "203.0.113.9", Type: "floating"},
		),
	}, nil)
	if !ok || via.InstanceID != "s-1" || viaAddr != "203.0.113.9" || door != "10.3.3.17" {
		t.Fatalf("got via=%v hop=%q door=%q ok=%v", via, viaAddr, door, ok)
	}
}

// Network names are project-scoped: the same name in another tenant is a
// different wire, and matching across projects would be the cross-farm guess
// this exists to avoid. A target whose project the collector could not resolve
// gets no jump for the same reason.
func TestTenantJumpStaysInsideTheProject(t *testing.T) {
	other := jumpSibling("s-2", "impostor", "p-2",
		store.InstanceAddress{NetworkName: "tenant-a", Address: "10.3.3.99"},
		store.InstanceAddress{Address: "203.0.113.7", Type: "floating"},
	)
	if _, _, _, ok := TenantJump(jumpTarget(), []store.Instance{other}, nil); ok {
		t.Error("jumped through a VM in another project")
	}
	unowned := jumpTarget()
	unowned.ProjectID = ""
	mine := jumpSibling("s-1", "worker-2", "",
		store.InstanceAddress{NetworkName: "tenant-a", Address: "10.3.3.18"},
		store.InstanceAddress{Address: "203.0.113.9", Type: "floating"},
	)
	if _, _, _, ok := TenantJump(unowned, []store.Instance{mine}, nil); ok {
		t.Error("jumped although neither project is known")
	}
}

// A hop has to be a machine that is up and still listed. SHUTOFF holds the
// address without answering on it, and a missing VM's address may belong to
// whoever holds it now.
func TestTenantJumpSkipsWhatCannotCarryTheHop(t *testing.T) {
	down := jumpSibling("s-1", "worker-2", "p-1",
		store.InstanceAddress{NetworkName: "tenant-a", Address: "10.3.3.18"},
		store.InstanceAddress{Address: "203.0.113.9", Type: "floating"},
	)
	down.Status = "SHUTOFF"
	gone := jumpSibling("s-2", "worker-3", "p-1",
		store.InstanceAddress{NetworkName: "tenant-a", Address: "10.3.3.19"},
		store.InstanceAddress{Address: "203.0.113.10", Type: "floating"},
	)
	since := time.Now()
	gone.MissingSince = &since
	self := jumpTarget() // the target is never its own hop
	wrongNet := jumpSibling("s-3", "elsewhere", "p-1",
		store.InstanceAddress{NetworkName: "tenant-b", Address: "10.9.9.9"},
		store.InstanceAddress{Address: "203.0.113.11", Type: "floating"},
	)
	if _, _, _, ok := TenantJump(jumpTarget(), []store.Instance{down, gone, self, wrongNet}, nil); ok {
		t.Error("picked a hop that cannot carry the connection")
	}
}

// A floating hop beats an operator-network hop, and at equal rank the pick is
// by name — the same request goes through the same door every time, so the
// audit trail reads as a route rather than a coin flip.
func TestTenantJumpPicksDeterministically(t *testing.T) {
	operator := jumpSibling("s-1", "aaa-worker", "p-1",
		store.InstanceAddress{NetworkName: "tenant-a", Address: "10.3.3.18"},
		store.InstanceAddress{NetworkName: "ops", Address: "192.168.1.4"},
	)
	floating := jumpSibling("s-2", "zzz-worker", "p-1",
		store.InstanceAddress{NetworkName: "tenant-a", Address: "10.3.3.19"},
		store.InstanceAddress{Address: "203.0.113.9", Type: "floating"},
	)
	via, viaAddr, _, ok := TenantJump(jumpTarget(), []store.Instance{operator, floating}, []string{"192.168."})
	if !ok || via.InstanceID != "s-2" || viaAddr != "203.0.113.9" {
		t.Fatalf("floating hop should win: via=%v addr=%q", via, viaAddr)
	}

	second := jumpSibling("s-3", "aaa-worker", "p-1",
		store.InstanceAddress{NetworkName: "tenant-a", Address: "10.3.3.20"},
		store.InstanceAddress{Address: "203.0.113.10", Type: "floating"},
	)
	via, _, _, ok = TenantJump(jumpTarget(), []store.Instance{floating, second}, nil)
	if !ok || via.Name != "aaa-worker" {
		t.Fatalf("equal rank should pick by name: %v", via)
	}
}
