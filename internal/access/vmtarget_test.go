package access

import (
	"errors"
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

// A VM with only tenant addresses is not a target. Refusing has to name what it
// found and point at the door that does not pretend to know which machine that
// address belongs to.
func TestVMTargetRefusesATenantOnlyAddress(t *testing.T) {
	_, err := VMTarget("vm-1", vmAddrs([2]string{"10.3.1.7", "fixed"}),
		VMPolicy{User: "rocky", OperatorNets: []string{"192.168."}})
	if err == nil {
		t.Fatal("a tenant address was accepted as a connection target")
	}
	for _, want := range []string{"10.3.1.7", "vctl ssh"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, missing %q", err, want)
		}
	}
}

// Having no addresses at all is a different sentence from having none worth
// connecting to, and the message has to say which.
func TestVMTargetSeparatesNoAddressFromNoUsableAddress(t *testing.T) {
	none, _ := VMTarget("vm-1", nil, VMPolicy{User: "rocky"})
	_ = none
	errNone := func() error { _, e := VMTarget("vm-1", nil, VMPolicy{User: "rocky"}); return e }()
	errTenant := func() error {
		_, e := VMTarget("vm-1", vmAddrs([2]string{"10.3.1.7", "fixed"}), VMPolicy{User: "rocky"})
		return e
	}()
	if errNone == nil || errTenant == nil {
		t.Fatal("both cases must refuse")
	}
	if errNone.Error() == errTenant.Error() {
		t.Errorf("both refusals read the same: %q", errNone)
	}
}

// The tenant-only refusal is typed, because a caller that knows a safe hop
// (openstack.TenantJump) recovers from exactly this error and no other — a
// missing user or a VM with no address at all must not be "fixed" by jumping.
func TestTheTenantOnlyRefusalIsTyped(t *testing.T) {
	_, err := VMTarget("vm", []store.InstanceAddress{{Address: "10.3.3.17"}}, VMPolicy{User: "ubuntu"})
	if !errors.Is(err, ErrNoVouchedAddress) {
		t.Fatalf("tenant-only refusal is not ErrNoVouchedAddress: %v", err)
	}
	_, err = VMTarget("vm", nil, VMPolicy{User: "ubuntu"})
	if errors.Is(err, ErrNoVouchedAddress) {
		t.Error("no-address refusal wrongly matches ErrNoVouchedAddress")
	}
	_, err = VMTarget("vm", []store.InstanceAddress{{Address: "10.3.3.17"}}, VMPolicy{})
	if errors.Is(err, ErrNoVouchedAddress) {
		t.Error("missing-user refusal wrongly matches ErrNoVouchedAddress")
	}
}

// VMTargetVia states the hop explicitly: tenant door as the target, the
// vouched sibling as the jump, one identity across both hops.
func TestVMTargetViaBuildsTheTwoHops(t *testing.T) {
	tgt := VMTargetVia("worker-1", "10.3.3.17", "worker-2", "203.0.113.9",
		VMPolicy{User: "ubuntu", CARole: "vm"})
	if tgt.Addr != "10.3.3.17:22" || tgt.User != "ubuntu" || tgt.Role != "vm" {
		t.Fatalf("target hop wrong: %+v", tgt)
	}
	if tgt.Jump == nil || tgt.Jump.Addr != "203.0.113.9:22" || tgt.Jump.Name != "worker-2" ||
		tgt.Jump.User != "ubuntu" || tgt.Jump.Role != "vm" {
		t.Fatalf("jump hop wrong: %+v", tgt.Jump)
	}
	if tgt.SkipDirect {
		t.Error("direct must still be tried first: a VPN that routes the tenant range skips the hop")
	}
}

// The walk advances only past an authentication refusal: a route that is down
// answers the same for every user, and retrying a different name over it
// learns nothing while costing a certificate per try.
func TestTryLoginUsersAdvancesOnlyPastAuthRefusals(t *testing.T) {
	authErr := errors.New("x handshake: ssh: unable to authenticate, attempted methods [none publickey]")

	tried := []string{}
	var toldRejected, toldNext string
	used, err := TryLoginUsers([]string{"root", "ubuntu"}, func(u string) error {
		tried = append(tried, u)
		if u == "root" {
			return authErr
		}
		return nil
	}, func(u, next string) { toldRejected, toldNext = u, next })
	if used != "ubuntu" || err != nil || len(tried) != 2 {
		t.Fatalf("used=%q err=%v tried=%v", used, err, tried)
	}
	if toldRejected != "root" || toldNext != "ubuntu" {
		t.Errorf("rejected callback got (%q, %q)", toldRejected, toldNext)
	}

	// A network failure stops the walk where it stands.
	netErr := errors.New("dial tcp 10.0.0.5:22: i/o timeout")
	tried = nil
	used, err = TryLoginUsers([]string{"root", "ubuntu"}, func(u string) error {
		tried = append(tried, u)
		return netErr
	}, nil)
	if used != "root" || !errors.Is(err, netErr) || len(tried) != 1 {
		t.Fatalf("network error: used=%q err=%v tried=%v", used, err, tried)
	}

	// Every candidate refusing returns the last refusal, as itself.
	used, err = TryLoginUsers([]string{"root", "ubuntu"}, func(string) error { return authErr }, nil)
	if used != "ubuntu" || !errors.Is(err, authErr) {
		t.Fatalf("all refused: used=%q err=%v", used, err)
	}
}
