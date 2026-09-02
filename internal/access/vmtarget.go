package access

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/openstack"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// VMPolicy is what the inventory supplies for a physical host and nobody
// supplies for a VM.
//
// Nova knows a server's addresses and nothing about how to log into it. The
// login user depends on the image — rocky, ubuntu, cloud-user — and no field
// carries it; the port is whatever the image's sshd uses; the CA role is a
// decision about which signing role this connection should present. All three
// have to come from configuration or the command line, and pretending otherwise
// would mean guessing a username and blaming the VM when it is refused.
type VMPolicy struct {
	User         string
	Port         int
	CARole       string
	OperatorNets []string
}

// ErrNoVouchedAddress is the refusal VMTarget answers when every address a VM
// has is one connecting to would be a guess. Callers that know a safe hop —
// a sibling on the same tenant network, found by openstack.TenantJump — test
// for it and build the route with VMTargetVia instead.
var ErrNoVouchedAddress = errors.New("no floating or operator-network address")

// VMTarget builds an SSH target for a Nova instance.
//
// No invented jump chain. A jump host is inventory topology and a VM has none —
// the address either routes from here or it does not, and inventing a hop would
// be a guess about a network this data does not describe. The one hop that is
// not invented — a same-project sibling holding a port on the same tenant
// network — is the caller's to find (openstack.TenantJump) and to state
// explicitly through VMTargetVia.
//
// The address comes from openstack.ConnectableAddress, which is stricter than
// what the listing prints. A listing showing a tenant address is showing what it
// knows; connecting to one is a guess about which machine answers. Tenant
// networks are per-deployment and reuse the same RFC1918 ranges — two farms both
// holding 10.3.1.7 is normal — so the only addresses accepted here are the ones
// that say something about reachability: a floating address, or one on a network
// this fleet routes.
func VMTarget(name string, addrs []store.InstanceAddress, p VMPolicy) (*sshc.Target, error) {
	// The caller's own mistake first. Reporting the VM's addresses to somebody
	// who has not said who to log in as makes them fix two things in two runs.
	if p.User == "" {
		return nil, fmt.Errorf("no login user for %s: a VM does not carry one, so pass --user", name)
	}
	addr := openstack.ConnectableAddress(addrs, p.OperatorNets)
	if addr == "" {
		if len(addrs) == 0 {
			// A real state: a VM that is building, or one whose port was
			// detached.
			return nil, fmt.Errorf("%s has no address at all", name)
		}
		// It has addresses; none of them is one this can vouch for. Say which
		// they are and name the door that does not pretend to know.
		known := make([]string, 0, len(addrs))
		for _, a := range addrs {
			known = append(known, a.Address)
		}
		return nil, fmt.Errorf(
			"%s has %w (only %s); "+
				"tenant ranges repeat across farms, so connecting to one would be a guess. "+
				"Use 'vctl ssh <user>@<addr>' if you know that address is this VM",
			name, ErrNoVouchedAddress, strings.Join(known, ", "))
	}
	port := p.Port
	if port == 0 {
		port = 22
	}
	return &sshc.Target{
		Name: name,
		Addr: net.JoinHostPort(addr, strconv.Itoa(port)),
		User: p.User,
		Role: p.CARole,
	}, nil
}

// VMTargetVia builds the two-hop target for a VM that only its tenant network
// holds: the sibling with the vouched address is the jump, and the tenant
// address is dialed from inside that network. The dialer still tries the
// target directly first — an operator whose VPN routes the tenant range
// connects without the hop, and everyone else falls through it.
//
// Both hops use the same login user and signing role: the siblings this is for
// are cluster machines stamped from the same image, and a hop that needs a
// different identity is one the operator should build by hand with
// 'vctl ssh <user>@<addr>'.
func VMTargetVia(name, tenantAddr, viaName, viaAddr string, p VMPolicy) *sshc.Target {
	port := p.Port
	if port == 0 {
		port = 22
	}
	return &sshc.Target{
		Name: name,
		Addr: net.JoinHostPort(tenantAddr, strconv.Itoa(port)),
		User: p.User,
		Role: p.CARole,
		Jump: &sshc.Target{
			Name: viaName,
			Addr: net.JoinHostPort(viaAddr, strconv.Itoa(port)),
			User: p.User,
			Role: p.CARole,
		},
	}
}

// NovaID extracts the instance id from what somebody typed.
//
// Kubernetes writes a node's provider as openstack:///<uuid>, so that string is
// in kubectl output, in manifests, and in anything a person is likely to paste.
// Accepting it saves the step of trimming a prefix by hand and getting it
// wrong.
//
// ok is false for anything that is not one of those two shapes. This path is
// the exact-identity one — a name that fits several VMs has to be refused, not
// resolved by position — so a value that is not an identifier is rejected here
// rather than turned into a search.
func NovaID(v string) (string, bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "openstack:///")
	if isUUID(v) {
		return v, true
	}
	return "", false
}

// isUUID tests the shape rather than parsing: 8-4-4-4-12 hex.
func isUUID(v string) bool {
	if len(v) != 36 {
		return false
	}
	for i, c := range v {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
