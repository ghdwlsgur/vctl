package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

// wgHandshakeWindow is how recently a peer must have completed a handshake to
// read as an active tunnel. WireGuard rekeys roughly every ~2 min while traffic
// flows, so 3 min catches live tunnels without flapping.
const wgHandshakeWindow = 3 * time.Minute

// wgGraphCmd renders the collected WireGuard topology, as a terminal summary or
// a mermaid diagram. Read (default-allow).
func wgGraphCmd(env CommandEnv) *cobra.Command {
	var format, hostFilter string
	cmd := &cobra.Command{
		Use:     "graph",
		Aliases: []string{"show"},
		Short:   "Render the WireGuard topology (terminal or mermaid)",
		Long: `graph reads the collected WireGuard data (run 'vctl wg sync' first) and
renders it as an aligned terminal summary (default) or a mermaid diagram
(--format mermaid) you can paste into docs. Peers are matched to the far-end
gateway by public key when both ends were collected.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				ifaces, err := st.WGInterfaces(cmd.Context())
				if err != nil {
					return err
				}
				peers, err := st.WGPeers(cmd.Context())
				if err != nil {
					return err
				}
				if hostFilter != "" {
					ifaces, peers = filterWGByHost(ifaces, peers, hostFilter)
				}
				if len(ifaces) == 0 {
					ui.Warnf(os.Stderr, "no WireGuard data. Run 'vctl wg sync --all' first.")
					return nil
				}
				switch format {
				case "mermaid":
					fmt.Fprintln(os.Stdout, wgMermaid(ifaces, peers))
				case "terminal", "":
					renderWGTerminal(os.Stdout, ifaces, peers)
				default:
					return fmt.Errorf("unknown --format %q (terminal|mermaid)", format)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "terminal", "output format: terminal|mermaid")
	cmd.Flags().StringVar(&hostFilter, "host", "", "restrict to one gateway host")
	registerCompletion(cmd, "host", completeInventoryHost(env))
	return gate(cmd, "wg")
}

func filterWGByHost(ifaces []store.WGInterfaceRow, peers []store.WGPeerRow, host string) ([]store.WGInterfaceRow, []store.WGPeerRow) {
	var fi []store.WGInterfaceRow
	for _, i := range ifaces {
		if i.Host == host {
			fi = append(fi, i)
		}
	}
	var fp []store.WGPeerRow
	for _, p := range peers {
		if p.Host == host {
			fp = append(fp, p)
		}
	}
	return fi, fp
}

func wgHandshakeCell(hs *time.Time) string {
	if hs == nil || hs.IsZero() {
		return ui.Muted("no-hs")
	}
	age := time.Since(*hs)
	if age <= wgHandshakeWindow {
		return ui.OK("up")
	}
	return ui.Warn("idle " + ui.CompactDuration(age))
}

// renderWGTerminal prints the topology grouped by gateway host, each interface
// with its peers, far-end resolution, allowed-ips and tunnel liveness.
func renderWGTerminal(w io.Writer, ifaces []store.WGInterfaceRow, peers []store.WGPeerRow) {
	idx := wireguard.BuildEndpointIndex(ifaces)
	peersByIface := map[string][]store.WGPeerRow{}
	for _, p := range peers {
		k := p.Host + "\x00" + p.Iface
		peersByIface[k] = append(peersByIface[k], p)
	}

	order, hosts := groupIfacesByHost(ifaces)
	for _, host := range order {
		his := hosts[host]
		fmt.Fprintln(w, ui.GroupHeading(host, fmt.Sprintf("%d iface", len(his))))
		for _, i := range his {
			port := ui.Muted("(no listen)")
			if i.ListenPort > 0 {
				port = fmt.Sprintf(":%d", i.ListenPort)
			}
			addr := ui.Muted("-")
			if len(i.Address) > 0 {
				addr = strings.Join(i.Address, ",")
			}
			fmt.Fprintf(w, "  %s  %s  %s  %s\n",
				ui.Value(i.Iface), port, addr, ui.Muted("pub "+wireguard.ShortKey(i.PublicKey)))
			for _, p := range peersByIface[i.Host+"\x00"+i.Iface] {
				far := ui.Muted("external")
				if r, ok := idx.Lookup(p.PeerPubKey); ok {
					far = r.Host + "/" + r.Iface
				} else if p.Endpoint != "" {
					far = p.Endpoint
				}
				allowed := ui.Muted("-")
				if len(p.AllowedIPs) > 0 {
					allowed = strings.Join(p.AllowedIPs, ",")
				}
				label := ""
				if p.Label != "" {
					label = "  " + ui.Muted("("+p.Label+")")
				}
				fmt.Fprintf(w, "      → %s  %s  %s  %s%s\n",
					ui.PadRight(far, 28), ui.PadRight(allowed, 40),
					wireguard.ShortKey(p.PeerPubKey), wgHandshakeCell(p.LatestHandshake), label)
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, ui.Muted(fmt.Sprintf("%d interfaces, %d peers", len(ifaces), len(peers))))
}

// groupIfacesByHost buckets interfaces by gateway — hosts sorted by name,
// each bucket sorted by interface. Shared by the terminal and mermaid
// renderers, whose copies of this block were already identical byte for byte.
func groupIfacesByHost(ifaces []store.WGInterfaceRow) ([]string, map[string][]store.WGInterfaceRow) {
	hosts := map[string][]store.WGInterfaceRow{}
	var order []string
	for _, i := range ifaces {
		if _, ok := hosts[i.Host]; !ok {
			order = append(order, i.Host)
		}
		hosts[i.Host] = append(hosts[i.Host], i)
	}
	sort.Strings(order)
	for _, his := range hosts {
		sort.Slice(his, func(a, b int) bool { return his[a].Iface < his[b].Iface })
	}
	return order, hosts
}

// wgMermaid renders the topology as a mermaid graph. Each gateway is a subgraph
// of its interfaces; each peer is an edge to the far-end interface (resolved by
// public key) or to an external node (endpoint/allowed-ips) when the far end was
// not collected. Bidirectional peers collapse to a single edge.
func wgMermaid(ifaces []store.WGInterfaceRow, peers []store.WGPeerRow) string {
	idx := wireguard.BuildEndpointIndex(ifaces)

	var b strings.Builder
	b.WriteString("graph LR\n")

	// Subgraph per host, interfaces as nodes.
	order, hosts := groupIfacesByHost(ifaces)
	for _, host := range order {
		his := hosts[host]
		fmt.Fprintf(&b, "  subgraph %s[\"%s\"]\n", mermaidID(host), mermaidLabel(host))
		for _, i := range his {
			label := i.Iface
			if i.ListenPort > 0 {
				label += fmt.Sprintf(" :%d", i.ListenPort)
			}
			fmt.Fprintf(&b, "    %s[\"%s\"]\n", ifaceNode(i.Host, i.Iface), mermaidLabel(label))
		}
		b.WriteString("  end\n")
	}

	// Edges. Sort peers for deterministic output.
	sorted := append([]store.WGPeerRow{}, peers...)
	sort.Slice(sorted, func(a, b int) bool {
		if sorted[a].Host != sorted[b].Host {
			return sorted[a].Host < sorted[b].Host
		}
		if sorted[a].Iface != sorted[b].Iface {
			return sorted[a].Iface < sorted[b].Iface
		}
		return sorted[a].PeerPubKey < sorted[b].PeerPubKey
	})
	seen := map[string]bool{}
	extDefined := map[string]bool{}
	for _, p := range sorted {
		from := ifaceNode(p.Host, p.Iface)
		label := mermaidLabel(strings.Join(p.AllowedIPs, ", "))
		if r, ok := idx.Lookup(p.PeerPubKey); ok {
			to := ifaceNode(r.Host, r.Iface)
			key := from + "|" + to
			rev := to + "|" + from
			if seen[key] || seen[rev] {
				continue
			}
			seen[key] = true
			fmt.Fprintf(&b, "  %s ---|\"%s\"| %s\n", from, label, to)
			continue
		}
		// External far end: node keyed by short public key.
		ext := "ext_" + mermaidID(wireguard.ShortKey(p.PeerPubKey))
		if !extDefined[ext] {
			extLabel := p.Endpoint
			if extLabel == "" {
				extLabel = wireguard.ShortKey(p.PeerPubKey)
			}
			fmt.Fprintf(&b, "  %s[\"%s\"]\n", ext, mermaidLabel(extLabel))
			extDefined[ext] = true
		}
		fmt.Fprintf(&b, "  %s ---|\"%s\"| %s\n", from, label, ext)
	}
	return b.String()
}

func ifaceNode(host, iface string) string { return mermaidID(host + "_" + iface) }

// mermaidID makes a mermaid-safe node id: alphanumerics kept, everything else
// becomes '_'.
func mermaidID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// mermaidLabel escapes a quoted node/edge label for mermaid.
func mermaidLabel(s string) string {
	if s == "" {
		return " "
	}
	return strings.ReplaceAll(s, "\"", "'")
}
