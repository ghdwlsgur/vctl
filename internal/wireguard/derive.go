package wireguard

import (
	"sort"
	"strings"
)

// Derived is what the declared topology implies once it is joined to the
// collected graph: which physical failure takes which tunnels with it, the hop
// chain each carried network actually rides, and the masquerades that chain
// requires. None of it is stored. It is recomputed from entities, relations and
// the collected graph on every build, so it cannot drift from them — and the
// page can draw an architecture from it without knowing any site by name.
type Derived struct {
	FailureDomains []FailureDomain `json:"failure_domains"`
	Paths          []Path          `json:"paths"`
	SNAT           []SNATRule      `json:"snat"`
	Gaps           []Gap           `json:"gaps,omitempty"`
}

// FailureDomain is one physical host and everything in the overlay that stops
// when it does.
type FailureDomain struct {
	Host  string `json:"host"` // host| node id
	Label string `json:"label"`
	Farm  string `json:"farm,omitempty"`
	Site  string `json:"site,omitempty"`
	// Dependents are the VMs and gateways placed on the host; Tunnels are the
	// subset that terminates a tunnel; Carries counts the networks those tunnels
	// carry, which is the blast radius in the unit an operator feels it.
	Dependents []string `json:"dependents"`
	Tunnels    []string `json:"tunnels"`
	Carries    int      `json:"carries"`
}

// Path is one carried network and the chain it rides, source side outward:
// the tunnel endpoint, the machine and farm it sits on, the underlay it
// transits, and the network itself.
type Path struct {
	Network string   `json:"network"`
	CIDR    string   `json:"cidr,omitempty"`
	Tunnel  string   `json:"tunnel"` // node id carrying it: a gateway, or a declared tunnel nobody synced
	Method  string   `json:"method"` // direct | proxy | dnat
	SNATAt  string   `json:"snat_at,omitempty"`
	Hops    []string `json:"hops"`
	// Uncollected marks a path whose tunnel exists only as a declaration. It is
	// drawn, because the operator says it is there, and flagged, because
	// nothing has confirmed it.
	Uncollected bool `json:"uncollected,omitempty"`
}

// SNATRule is a masquerade the declared paths require to exist. It is the
// shape a NAT contract asserts against a live ruleset: on this host, traffic
// from this tunnel to this network must leave masqueraded, on these interfaces
// when the declaration pins them.
type SNATRule struct {
	At      string   `json:"at"`
	Tunnel  string   `json:"tunnel"`
	Iface   string   `json:"iface,omitempty"` // the WireGuard interface the rule matches as iif
	Network string   `json:"network"`
	CIDR    string   `json:"cidr,omitempty"`
	OIF     []string `json:"oif,omitempty"`
	Table   string   `json:"table,omitempty"`
}

// Gap is a declaration the collected graph could not corroborate, or a
// declared object nothing else refers to. Each is one line the page should
// show rather than silently draw around.
type Gap struct {
	Kind    string `json:"kind"` // uncollected-tunnel | uncarried-network | unplaced-vm | placement-conflict
	Subject string `json:"subject"`
	Detail  string `json:"detail,omitempty"`
}

// Derive computes the derived view of a topology that already carries declared
// nodes and links. On a graph with nothing declared it returns empty slices,
// not nil, so the JSON shape is stable for the page.
func Derive(topo Topology) Derived {
	g := newGraphIndex(topo)
	d := Derived{
		FailureDomains: g.failureDomains(),
		Paths:          []Path{},
		SNAT:           []SNATRule{},
	}
	for _, l := range topo.Links {
		if l.Kind != "carries" {
			continue
		}
		p := g.path(l)
		d.Paths = append(d.Paths, p)
		if p.Method == "direct" && p.SNATAt != "" {
			d.SNAT = append(d.SNAT, SNATRule{
				At: p.SNATAt, Tunnel: p.Tunnel, Iface: attrString(l.Attrs, "iface"), Network: p.Network, CIDR: p.CIDR,
				OIF: attrStrings(l.Attrs, "oif"), Table: attrString(l.Attrs, "nft_table"),
			})
		}
	}
	sort.Slice(d.Paths, func(i, j int) bool {
		a, b := d.Paths[i], d.Paths[j]
		if a.Network != b.Network {
			return a.Network < b.Network
		}
		if a.Tunnel != b.Tunnel {
			return a.Tunnel < b.Tunnel
		}
		return a.Method < b.Method
	})
	sort.Slice(d.SNAT, func(i, j int) bool {
		a, b := d.SNAT[i], d.SNAT[j]
		if a.At != b.At {
			return a.At < b.At
		}
		if a.Tunnel != b.Tunnel {
			return a.Tunnel < b.Tunnel
		}
		return a.Network < b.Network
	})
	d.Gaps = g.gaps()
	return d
}

// graphIndex is the topology turned inside out: by id, and by (endpoint, kind)
// in both directions, so the derivations read as walks rather than scans.
type graphIndex struct {
	nodes map[string]*Node
	out   map[string]map[string][]Link // source → kind → links
	in    map[string]map[string][]Link // target → kind → links
}

func newGraphIndex(topo Topology) *graphIndex {
	g := &graphIndex{
		nodes: make(map[string]*Node, len(topo.Nodes)),
		out:   map[string]map[string][]Link{},
		in:    map[string]map[string][]Link{},
	}
	for i := range topo.Nodes {
		g.nodes[topo.Nodes[i].ID] = &topo.Nodes[i]
	}
	for _, l := range topo.Links {
		if g.out[l.Source] == nil {
			g.out[l.Source] = map[string][]Link{}
		}
		if g.in[l.Target] == nil {
			g.in[l.Target] = map[string][]Link{}
		}
		g.out[l.Source][l.Kind] = append(g.out[l.Source][l.Kind], l)
		g.in[l.Target][l.Kind] = append(g.in[l.Target][l.Kind], l)
	}
	return g
}

// parentOf is the machine a node runs on: what the sync recorded, else what
// the operator declared. Empty for physical hosts and for anything unplaced.
func (g *graphIndex) parentOf(id string) string {
	if n, ok := g.nodes[id]; ok && n.Parent != "" {
		return n.Parent
	}
	for _, l := range g.out[id]["placed-on"] {
		return l.Target
	}
	return ""
}

// memberOf follows member-of to the first target of the given kind.
func (g *graphIndex) memberOf(id, kind string) string {
	for _, l := range g.out[id]["member-of"] {
		if n, ok := g.nodes[l.Target]; ok && n.Kind == kind {
			return l.Target
		}
	}
	return ""
}

// machineOf resolves a carrying node to the VM it is, when it is one. A
// collected gateway is already the machine; a declared tunnel names its host
// in attrs, and that host is a declared VM when one carries the same name.
func (g *graphIndex) machineOf(id string) string {
	n, ok := g.nodes[id]
	if !ok {
		return ""
	}
	if n.Kind != "tunnel" {
		return id
	}
	host := attrString(n.Attrs, "host")
	if host == "" {
		return ""
	}
	if _, ok := g.nodes["vm/"+host]; ok {
		return "vm/" + host
	}
	if _, ok := g.nodes[host]; ok {
		return host
	}
	return ""
}

func (g *graphIndex) failureDomains() []FailureDomain {
	// Every placed node contributes to its host's domain, whether the placement
	// came from the sync (Parent) or the declaration (placed-on).
	deps := map[string][]string{}
	for id := range g.nodes {
		if p := g.parentOf(id); p != "" {
			deps[p] = append(deps[p], id)
		}
	}
	// A declared tunnel that nobody synced still fails with the VM it names.
	for id, n := range g.nodes {
		if n.Kind != "tunnel" {
			continue
		}
		if m := g.machineOf(id); m != "" {
			if p := g.parentOf(m); p != "" {
				deps[p] = append(deps[p], id)
			}
		}
	}
	var out []FailureDomain
	for id, n := range g.nodes {
		if n.Kind != "physical-host" {
			continue
		}
		fd := FailureDomain{Host: id, Label: n.Label, Farm: g.memberOf(id, "farm"), Site: n.DC}
		if fd.Farm != "" && fd.Site == "" {
			fd.Site = g.memberOf(fd.Farm, "site")
		}
		fd.Dependents = uniqueSorted(deps[id])
		for _, d := range fd.Dependents {
			if g.terminatesTunnel(d) {
				fd.Tunnels = append(fd.Tunnels, d)
				fd.Carries += len(g.out[d]["carries"])
			}
		}
		if fd.Dependents == nil {
			fd.Dependents = []string{}
		}
		if fd.Tunnels == nil {
			fd.Tunnels = []string{}
		}
		out = append(out, fd)
	}
	sort.Slice(out, func(i, j int) bool {
		// Widest blast radius first; the page shows these top-down. Networks
		// carried outranks endpoints hosted: one hub carrying nine networks is
		// a bigger loss than two mesh peers carrying none.
		if out[i].Carries != out[j].Carries {
			return out[i].Carries > out[j].Carries
		}
		if len(out[i].Tunnels) != len(out[j].Tunnels) {
			return len(out[i].Tunnels) > len(out[j].Tunnels)
		}
		return out[i].Host < out[j].Host
	})
	if out == nil {
		out = []FailureDomain{}
	}
	return out
}

// terminatesTunnel reports whether a node is a tunnel endpoint: it owns
// WireGuard interfaces, or it is a declared tunnel nobody synced. Kind alone
// cannot say — a collected gateway annotated as a VM is drawn as kind "vm".
func (g *graphIndex) terminatesTunnel(id string) bool {
	n, ok := g.nodes[id]
	if !ok {
		return false
	}
	return n.Kind == "gateway" || n.Kind == "tunnel" || len(n.Ifaces) > 0
}

// path lays one carries link out as hops. The chain climbs from the tunnel to
// its machine, host, farm and site, then follows the declared transits in
// order, and ends at the network.
func (g *graphIndex) path(l Link) Path {
	p := Path{
		Network: l.Target, Tunnel: l.Source,
		Method: attrString(l.Attrs, "method"), SNATAt: attrString(l.Attrs, "snat_at"),
	}
	if n, ok := g.nodes[l.Target]; ok {
		p.CIDR = attrString(n.Attrs, "cidr")
	}
	if n, ok := g.nodes[l.Source]; ok && n.Kind == "tunnel" {
		p.Uncollected = true
	}
	hops := []string{l.Source}
	push := func(id string) {
		if id != "" && hops[len(hops)-1] != id {
			hops = append(hops, id)
		}
	}
	cur := l.Source
	if m := g.machineOf(cur); m != "" {
		push(m)
		cur = m
	}
	if host := g.parentOf(cur); host != "" {
		push(host)
		cur = host
	}
	farm := g.memberOf(cur, "farm")
	push(farm)
	if farm != "" {
		push(g.memberOf(farm, "site"))
	} else {
		push(g.memberOf(cur, "site"))
	}
	transits := append([]Link(nil), g.out[l.Source]["transits"]...)
	sort.Slice(transits, func(i, j int) bool {
		return attrNumber(transits[i].Attrs, "order") < attrNumber(transits[j].Attrs, "order")
	})
	for _, t := range transits {
		push(t.Target)
	}
	push(l.Target)
	p.Hops = hops
	return p
}

func (g *graphIndex) gaps() []Gap {
	var out []Gap
	for id, n := range g.nodes {
		// The sync recorded one host under a machine and the operator declared
		// another. Whichever is right, the picture would be lying about one of
		// them, so it is reported before either is drawn as fact.
		if n.Parent != "" {
			for _, l := range g.out[id]["placed-on"] {
				if l.Target != n.Parent {
					out = append(out, Gap{Kind: "placement-conflict", Subject: id,
						Detail: "synced on " + n.Parent + ", declared on " + l.Target})
				}
			}
		}
		switch n.Kind {
		case "tunnel":
			out = append(out, Gap{Kind: "uncollected-tunnel", Subject: id,
				Detail: "declared on " + attrString(n.Attrs, "host") + " but never synced"})
		case "network":
			if len(g.in[id]["carries"]) == 0 {
				out = append(out, Gap{Kind: "uncarried-network", Subject: id, Detail: "no tunnel carries it"})
			}
		case "vm":
			if g.parentOf(id) == "" {
				out = append(out, Gap{Kind: "unplaced-vm", Subject: id, Detail: "no placed-on host"})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

func attrString(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return strings.TrimSpace(s)
}

// attrStrings reads a list attr that may have arrived as a JSON array or as a
// single string.
func attrStrings(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}

// attrNumber reads a numeric attr; JSON decoding yields float64, the CLI may
// have stored an int, and a missing value sorts last.
func attrNumber(m map[string]any, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 1 << 30
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
