package access

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func vmAddrs(specs ...[2]string) []store.InstanceAddress {
	out := make([]store.InstanceAddress, 0, len(specs))
	for _, s := range specs {
		out = append(out, store.InstanceAddress{Address: s[0], Type: s[1]})
	}
	return out
}

// A VM is addressed by its Nova id only. A name fits several VMs across farms —
// this fleet has two called secloudit-pkg-bastion in different deployments — and
// resolving that by position would connect to whichever sorted first, which is
// a mistake nothing downstream can catch.
func TestNovaIDTakesAnIdentifierAndNothingElse(t *testing.T) {
	const id = "877c81c5-b417-425b-8f7d-d4930090c817"
	for _, in := range []string{id, "openstack:///" + id, "  " + id + "  "} {
		got, ok := NovaID(in)
		if !ok || got != id {
			t.Errorf("NovaID(%q) = %q, %v; want the id", in, got, ok)
		}
	}
	// A name is not an identifier, and turning it into a search here is the
	// thing this refuses to do.
	for _, in := range []string{"ai-platform-haproxy-1", "", "877c81c5", "openstack:///nope"} {
		if _, ok := NovaID(in); ok {
			t.Errorf("NovaID(%q) was accepted", in)
		}
	}
}

// The address is the ranked one, so what the listing shows is what a connection
// uses. Most VM addresses here are tenant networks a workstation cannot reach.
func TestVMTargetConnectsToTheReachableAddress(t *testing.T) {
	tgt, err := VMTarget("ai-platform-haproxy-1", vmAddrs(
		[2]string{"10.3.1.7", "fixed"},
		[2]string{"192.168.201.171", "fixed"},
	), VMPolicy{User: "rocky", CARole: "sre-core", OperatorNets: []string{"192.168."}})
	if err != nil {
		t.Fatalf("VMTarget: %v", err)
	}
	if tgt.Addr != "192.168.201.171:22" {
		t.Errorf("addr = %q, want the operator-network address", tgt.Addr)
	}
	if tgt.User != "rocky" || tgt.Role != "sre-core" {
		t.Errorf("target = %+v, want the supplied user and CA role", tgt)
	}
	// A jump host is inventory topology and a VM has none. Inventing a hop
	// would be a guess about a network this data does not describe.
	if tgt.Jump != nil {
		t.Error("a jump chain was invented for a VM")
	}
}

// Nova records no login user, and the answer depends on the image. Guessing one
// would blame the VM for refusing a name nobody chose.
func TestVMTargetRefusesWithoutALoginUser(t *testing.T) {
	_, err := VMTarget("vm-1", vmAddrs([2]string{"192.168.1.5", "fixed"}), VMPolicy{})
	if err == nil {
		t.Fatal("a target was built with no login user")
	}
	if !strings.Contains(err.Error(), "--user") {
		t.Errorf("error = %q, want it to say how to supply one", err)
	}
}

// A VM that is building, or one whose port was detached, has nowhere to connect
// to. That is a real state and the one case where this cannot be attempted.
func TestVMTargetRefusesWithNoAddress(t *testing.T) {
	if _, err := VMTarget("vm-1", nil, VMPolicy{User: "rocky"}); err == nil {
		t.Fatal("a target was built for a VM with no addresses")
	}
}
