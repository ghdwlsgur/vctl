package openstack

import (
	"testing"

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
