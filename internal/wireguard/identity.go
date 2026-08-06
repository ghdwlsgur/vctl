package wireguard

import (
	"sort"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// --- endpoint identity ---

// TunnelKey names one peer entry on one interface of one host. It is the
// identity a live sample is filed under, and the reason it is a struct rather
// than a joined string is that every part of it is needed to say which end of
// which tunnel a number belongs to.
type TunnelKey struct{ Host, Iface, Peer string }

// NodeRef is the far end of a peer resolved to a known interface.
type NodeRef struct{ Host, Iface string }

// EndpointIndex resolves a public key to the gateway that owns it, and keeps
// every hostname the key was observed under.
//
// The public key is the identity; the hostname is where it was seen. Collection
// walks the inventory host by host, so one machine reachable under two inventory
// names gets polled twice and lands in two rows. That is not a duplicate key in
// the usual sense — in the fleet this was written against, sre-lb is a VIP
// living on sre-srv-0049, and both entries describe the same interfaces down to
// the listen port and address.
//
// Conflict is the narrower case: one key observed with genuinely different
// interface settings, meaning two machines really are presenting one identity.
// Only that deserves a warning. Flagging the VIP case would report a normal
// arrangement as a fault, which is worse than saying nothing at all.
type EndpointIndex struct {
	canonical map[string]NodeRef   // public key → the gateway it is drawn as
	aliases   map[string][]NodeRef // public key → every (host, iface) it was seen at
	conflicts map[string]bool      // public key → the observations disagree
}

// lookup resolves a peer's public key to the gateway that owns it.
func (e EndpointIndex) Lookup(key string) (NodeRef, bool) {
	r, ok := e.canonical[key]
	return r, ok
}

// observedThrough returns the hostnames a key was seen under, sorted, and only
// when there is more than one. A single name is the ordinary case and says
// nothing worth putting on screen.
func (e EndpointIndex) ObservedThrough(key string) []string {
	var hosts []string
	seen := map[string]bool{}
	for _, r := range e.aliases[key] {
		if !seen[r.Host] {
			seen[r.Host] = true
			hosts = append(hosts, r.Host)
		}
	}
	if len(hosts) < 2 {
		return nil
	}
	sort.Strings(hosts)
	return hosts
}

// BuildEndpointIndex groups interfaces by public key and picks one canonical
// owner per key.
//
// The pick is the lexically smallest hostname rather than whichever row arrived
// last. Last-write-wins made the graph depend on scan order: the same database
// could render different edges between runs, and nothing on screen said so.
func BuildEndpointIndex(ifaces []store.WGInterfaceRow) EndpointIndex {
	byKey := make(map[string][]store.WGInterfaceRow, len(ifaces))
	for _, i := range ifaces {
		byKey[i.PublicKey] = append(byKey[i.PublicKey], i)
	}
	idx := EndpointIndex{
		canonical: make(map[string]NodeRef, len(byKey)),
		aliases:   make(map[string][]NodeRef, len(byKey)),
		conflicts: map[string]bool{},
	}
	for key, rows := range byKey {
		sort.Slice(rows, func(a, b int) bool {
			if rows[a].Host != rows[b].Host {
				return rows[a].Host < rows[b].Host
			}
			return rows[a].Iface < rows[b].Iface
		})
		for _, r := range rows {
			idx.aliases[key] = append(idx.aliases[key], NodeRef{r.Host, r.Iface})
		}
		idx.canonical[key] = NodeRef{rows[0].Host, rows[0].Iface}
		if !SameInterface(rows) {
			idx.conflicts[key] = true
		}
	}
	return idx
}

// SameInterface reports whether every observation describes one interface —
// same name, same listen port, same addresses. Anything else means two machines
// are presenting the same key, which is a real conflict rather than one machine
// seen under two names.
func SameInterface(rows []store.WGInterfaceRow) bool {
	first := rows[0]
	firstAddrs := append([]string{}, first.Address...)
	sort.Strings(firstAddrs)
	for _, r := range rows[1:] {
		if r.Iface != first.Iface || r.ListenPort != first.ListenPort {
			return false
		}
		addrs := append([]string{}, r.Address...)
		sort.Strings(addrs)
		if len(addrs) != len(firstAddrs) {
			return false
		}
		for i := range addrs {
			if addrs[i] != firstAddrs[i] {
				return false
			}
		}
	}
	return true
}

func ShortKey(k string) string {
	if len(k) <= 8 {
		return k
	}
	return k[:7] + "…"
}

// wgHandshakeCell renders a peer's tunnel liveness from its last handshake.
