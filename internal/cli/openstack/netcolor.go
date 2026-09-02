package openstack

import (
	"net/netip"
	"sort"

	"github.com/charmbracelet/lipgloss"

	osdomain "github.com/ghdwlsgur/vctl/internal/openstack"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// Coloring by network: every VM address on screen is painted by the network it
// sits on, so "which of these machines share a wire" is read at a glance
// rather than worked out address by address. The question that makes the
// colors worth having is the tenant jump (openstack.TenantJump): a tenant-only
// VM is reached through a same-network sibling holding a floating address, and
// nova lists a floating address under the network of the port it is bound to —
// so the door into a network and the machines behind it carry the same color.
//
// The key is (project, network name) — exactly the pair TenantJump matches on.
// Network names are project-scoped, and coloring by name alone would paint two
// projects' unrelated "private" networks as one wire: the cross-project jump
// the domain layer refuses would look possible on screen. Under-grouping is
// the safe error — a shared provider network shows one color per project, and
// nothing it promises is false. Rows collected before network_name existed
// fall back to the address band (/24 for IPv4, /64 for IPv6), still
// project-scoped for the same reason tenant ranges repeat across projects.

// netBandColors is the palette one farm's networks are dealt from, chosen away
// from the CLI's semantic colors (39 accent, 42 ok, 214 warn, 203 fail) so a
// network never reads as a verdict. Farms here run a handful of networks; past
// eight the palette cycles, which two networks sharing a color survives — the
// detail view still names them.
var netBandColors = []string{"81", "213", "222", "115", "177", "180", "117", "146"}

// netPalette maps a network key to its style. The zero value paints nothing,
// which is what the non-TUI listings get when nobody built one.
type netPalette map[string]lipgloss.Style

// newNetPalette deals colors to every network the given VMs sit on. Keys are
// sorted before assignment, so the mapping is a property of the farm's set of
// networks rather than of row order: a network keeps its color across
// refreshes, filters, and between the list and the detail behind enter.
func newNetPalette(vms []store.Instance) netPalette {
	seen := map[string]bool{}
	for _, v := range vms {
		for _, a := range v.Addresses {
			seen[vmNetKey(v, a)] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := netPalette{}
	for i, k := range keys {
		out[k] = lipgloss.NewStyle().Foreground(lipgloss.Color(netBandColors[i%len(netBandColors)]))
	}
	return out
}

func (p netPalette) paint(key, s string) string {
	if st, ok := p[key]; ok {
		return st.Render(s)
	}
	return s
}

// vmNetKey names the wire an address is on: the project plus the neutron
// network when the collection recorded it, the project plus the address band
// when it did not.
func vmNetKey(v store.Instance, a store.InstanceAddress) string {
	if a.NetworkName != "" {
		return v.ProjectID + "/" + a.NetworkName
	}
	return v.ProjectID + "/" + addrBand(a.Address)
}

// addrBand is the fallback grouping for addresses with no recorded network: the
// /24 an operator means when they say "the .201 network", /64 for IPv6. An
// unparseable address is its own band rather than an error — it can only have
// come from the database, and a listing must not refuse to draw over it.
func addrBand(addr string) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return addr
	}
	return p.String()
}

// addressCell is the ADDRESS column: the reachable address painted in its
// network's color, then one dot per further network the VM holds a port on,
// each in that network's color. The dots are what make the jump legible — a
// VM whose floating address is painted blue with no dots is the door into the
// blue network, and the tenant-only VMs whose addresses are painted blue are
// what it opens.
func addressCell(v store.Instance, operatorNets []string, pal netPalette) string {
	best, others := addressParts(v, operatorNets)
	if best == nil {
		return ""
	}
	out := pal.paint(vmNetKey(v, *best), best.Address)
	if len(others) > 0 {
		out += " "
		for _, k := range others {
			out += pal.paint(k, "●")
		}
	}
	return out
}

// addressParts resolves the address the listing shows back to its entry, and
// collects the keys of the VM's other networks — deduplicated, sorted, and
// without the shown one. The shown address is osdomain.PreferredAddress, the
// same ranking the SSH path uses, so the painted address is the one a
// connection will try first.
func addressParts(v store.Instance, operatorNets []string) (*store.InstanceAddress, []string) {
	shown := osdomain.PreferredAddress(v.Addresses, operatorNets)
	if shown == "" {
		return nil, nil
	}
	var best *store.InstanceAddress
	for i := range v.Addresses {
		if v.Addresses[i].Address == shown {
			best = &v.Addresses[i]
			break
		}
	}
	// PreferredAddress only returns an address from the slice, so best is set;
	// guarded anyway because a nil deref in a renderer takes the screen with it.
	if best == nil {
		return nil, nil
	}
	seen := map[string]bool{vmNetKey(v, *best): true}
	var others []string
	for _, a := range v.Addresses {
		if k := vmNetKey(v, a); !seen[k] {
			seen[k] = true
			others = append(others, k)
		}
	}
	sort.Strings(others)
	return best, others
}
