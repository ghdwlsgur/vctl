package access

import (
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

// VMTarget builds an SSH target for a Nova instance.
//
// No jump chain. A jump host is inventory topology and a VM has none — the
// address either routes from here or it does not, and inventing a hop would be
// a guess about a network this data does not describe. Same reasoning as the
// direct user@addr path.
//
// The address comes from openstack.ReachableAddress, the same ranking the VM
// listing prints, so the address on screen is the address this connects to. Of
// the VMs in this fleet most carry a tenant address that a workstation cannot
// reach at all, which is why the choice is a ranking rather than "the first
// one".
func VMTarget(name string, addrs []store.InstanceAddress, p VMPolicy) (*sshc.Target, error) {
	addr := openstack.ReachableAddress(addrs, p.OperatorNets)
	if addr == "" {
		// A real state — a VM that is building, or one whose port was detached —
		// and the one case where connecting cannot be attempted at all.
		return nil, fmt.Errorf("%s has no address to connect to", name)
	}
	if p.User == "" {
		return nil, fmt.Errorf("no login user for %s: a VM does not carry one, so pass --user", name)
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
