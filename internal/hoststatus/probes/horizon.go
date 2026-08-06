package probes

import (
	"bufio"
	"os"
	"sort"
	"strings"
)

// onOperatorNetwork reports whether an address is on a network people reach
// things from. Prefix matching rather than CIDR: the config says "192.168."
// because that is how somebody describes it.
func onOperatorNetwork(addr string, nets []string) bool {
	for _, n := range nets {
		if n != "" && strings.HasPrefix(addr, n) {
			return true
		}
	}
	return false
}

// Where a person points a browser to reach this farm's dashboard.
//
// Nowhere in the API tells you: Horizon is not in the service catalog, because
// it is not an API. The address exists on the host, in the haproxy frontend that
// fronts it, and that is the only place it can be read from without asking
// somebody who already knows.
//
// A farm binds Horizon more than once — internal and external, http and https —
// so this is a ranking rather than a lookup. What somebody wants is the address
// they can actually type, which is the external one, over TLS if it is offered.

// horizonConf is the haproxy frontend for the dashboard, written by Kolla.
const horizonConf = "/etc/kolla/haproxy/services.d/horizon.cfg"

// horizonURLs returns every address this farm's dashboard is bound to, best
// first, or nil.
//
// All of them, not just the best one. A farm binds Horizon on an operator
// network and on an internal VIP, and which one somebody needs depends on where
// they are sitting — from a controller the internal one is the shorter path, and
// from a laptop it is the only one that does not work. Reporting the best and
// discarding the rest answers for the reader.
//
// The config does not label a bind internal or external — they are all just
// addresses — so the order comes from the operator networks in config. That is a
// fact about the network rather than about OpenStack, which is why it is
// configured rather than derived.
func (p *OpenStack) horizonURLs() []string {
	f, err := os.Open(p.path(horizonConf))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	type bind struct {
		url  string
		rank int
	}
	var found []bind
	seen := map[string]bool{}
	read := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if read += len(line); read > maxConfScan {
			break
		}
		// Only the frontend binds. `server` lines name the backends, which are
		// the individual controllers and not somewhere anyone should be sent:
		// that path bypasses the VIP and breaks the moment that host is the one
		// being patched.
		rest, ok := strings.CutPrefix(line, "bind ")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		addr := fields[0]
		tls := strings.Contains(rest, " ssl ") || strings.HasSuffix(rest, " ssl")
		host, _, _ := strings.Cut(addr, ":")
		u := horizonScheme(tls) + trimDefaultPort(addr, tls)
		if seen[u] {
			continue
		}
		seen[u] = true
		found = append(found, bind{u, horizonRank(onOperatorNetwork(host, p.operatorNets), tls)})
	}
	// Stable within a rank, so a farm's list does not shuffle between probes
	// and look like a change when nothing moved.
	sort.SliceStable(found, func(i, j int) bool { return found[i].rank > found[j].rank })
	out := make([]string, 0, len(found))
	for _, b := range found {
		out = append(out, b.url)
	}
	return out
}

// horizonRank orders the binds by how useful the address is to a person.
//
// A reachable address beats an unreachable one outright: an internal VIP is
// correct and impossible to open from a laptop, and handing somebody that is
// worse than handing them nothing. TLS breaks the tie within each.
func horizonRank(reachable, tls bool) int {
	switch {
	case reachable && tls:
		return 4
	case reachable:
		return 3
	case tls:
		return 2
	default:
		return 1
	}
}

func horizonScheme(tls bool) string {
	if tls {
		return "https://"
	}
	return "http://"
}

// trimDefaultPort drops :80 and :443 — a URL that carries its own default port
// is noise, and this one is meant to be read rather than parsed.
func trimDefaultPort(addr string, tls bool) string {
	drop := ":80"
	if tls {
		drop = ":443"
	}
	return strings.TrimSuffix(addr, drop)
}
