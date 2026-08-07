package openstack

import (
	"strings"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// OnOperatorNetwork reports whether an address is on a network people reach
// things from.
//
// Prefix matching rather than CIDR: the config says "192.168." because that is
// how somebody describes it, and parsing it as a network would turn a typo into
// a silent no-match instead of an obvious one.
func OnOperatorNetwork(addr string, nets []string) bool {
	for _, n := range nets {
		if n != "" && strings.HasPrefix(addr, n) {
			return true
		}
	}
	return false
}

// PreferredAddress picks the address a VM is most likely to answer on from
// where a person is sitting.
//
// A VM has several and they are not interchangeable. A floating address is one
// somebody attached on purpose so the VM could be reached; an operator-network
// address is one this fleet routes; a tenant address is neither, and is the
// common case — of 216 VMs here, the majority of addresses are on 10.x networks
// that a workstation cannot reach at all.
//
// This is the policy, with no rendering in it. It used to live inside the VM
// listing's cell formatter, wrapped in a "(+2)" suffix and terminal styling,
// which meant the one place that needed the *address* — connecting to it —
// could not call it and would have grown a second copy of the ranking. Two
// implementations of "which address is the right one" disagree eventually, and
// the disagreement shows up as a connection to the wrong network.
//
// Best effort, and that is the right contract for a listing: an address
// somebody can try beats a blank column. It is the wrong contract for opening a
// connection — see ConnectableAddress.
//
// Empty when the VM has no addresses at all, which is a real state: a VM that
// is building, or one whose port was detached.
func PreferredAddress(addrs []store.InstanceAddress, operatorNets []string) string {
	best, bestRank := "", 0
	for _, a := range addrs {
		r := 1
		switch {
		case a.Type == "floating":
			r = 3
		case OnOperatorNetwork(a.Address, operatorNets):
			r = 2
		}
		if r > bestRank {
			best, bestRank = a.Address, r
		}
	}
	return best
}

// ConnectableAddress picks an address it is safe to open a connection to, or
// empty.
//
// The difference from PreferredAddress is the last rank. A listing showing a
// tenant address is showing what it knows; a connection made to one is a guess
// about which machine answers. Tenant networks are per-deployment and reuse the
// same RFC1918 ranges — two farms both holding 10.3.1.7 is the normal case, not
// a broken one — so "the only address I have" is not evidence that it belongs to
// the VM that was asked for.
//
// A floating address was attached so the VM could be reached from outside. An
// operator-network address is on a network this fleet routes and does not reuse.
// Either is a statement about reachability. Anything else is not, and the caller
// is told rather than connected somewhere.
func ConnectableAddress(addrs []store.InstanceAddress, operatorNets []string) string {
	best, bestRank := "", 0
	for _, a := range addrs {
		r := 0
		switch {
		case a.Type == "floating":
			r = 2
		case OnOperatorNetwork(a.Address, operatorNets):
			r = 1
		}
		if r > bestRank {
			best, bestRank = a.Address, r
		}
	}
	return best
}
