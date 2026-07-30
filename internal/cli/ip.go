package cli

import (
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// ipKinds are the allowed allocation categories for the 201.x ledger.
var ipKinds = []string{"personal", "server", "vm", "floating-ip", "router-gw", "dnat-vip"}

func ipCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ip",
		Short: "Manage the 192.168.201.0/24 IP allocation ledger (IPAM)",
		Long: `ip manages a hand-curated address ledger, separate from the sync-managed
inventory (servers). It records who/what holds each 192.168.201.x address —
personal devices, OpenStack VMs, floating IPs, DNAT VIPs and physical hosts —
so the ledger survives sync and covers non-SSH addresses too.`,
	}
	cmd.AddCommand(ipListCmd(), ipSetCmd(), ipRmCmd())
	return cmd
}

// ipListCmd prints the ledger, optionally filtered. Read (default-allow).
func ipListCmd() *cobra.Command {
	var kind, owner string
	cmd := &cobra.Command{
		Use:     "list [filter]",
		Aliases: []string{"ls"},
		Short:   "List IP allocations",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var filter string
			if len(args) == 1 {
				filter = args[0]
			}
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				rows, err := st.IPAllocList(cmd.Context(), kind, owner, filter)
				if err != nil {
					return err
				}
				if len(rows) == 0 {
					ui.Warnf(os.Stderr, "no allocations match. Seed the ledger or widen the filter.")
					return nil
				}
				renderIPAllocations(os.Stdout, rows)
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "", "filter by kind ("+joinKinds()+")")
	cmd.Flags().StringVar(&owner, "owner", "", "filter by owner substring")
	return gate(cmd, "ip", classRead)
}

// ipSetCmd creates or updates one allocation. Mutate (default-deny w/o grant).
func ipSetCmd() *cobra.Command {
	var a store.IPAllocation
	cmd := &cobra.Command{
		Use:   "set <ip>",
		Short: "Create or update an IP allocation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid IP: %q", ip)
			}
			if a.Kind == "" || !slices.Contains(ipKinds, a.Kind) {
				return fmt.Errorf("--kind is required and must be one of: %s", joinKinds())
			}
			if a.FarmVIP != "" && net.ParseIP(a.FarmVIP) == nil {
				return fmt.Errorf("invalid --farm-vip: %q", a.FarmVIP)
			}
			a.IP = ip
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.IPAllocUpsert(cmd.Context(), a); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "saved %s (%s)", ip, a.Kind)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&a.Owner, "owner", "", "owner: person or team")
	f.StringVar(&a.Kind, "kind", "", "kind: "+joinKinds())
	f.StringVar(&a.Label, "label", "", "target name (hostname / VM name / port / device)")
	f.StringVar(&a.Hostname, "hostname", "", "linked servers.hostname (kind=server)")
	f.StringVar(&a.OS, "os", "", "OS for a personal device (Mac/Windows)")
	f.StringVar(&a.Project, "project", "", "OpenStack project or purpose")
	f.StringVar(&a.Farm, "farm", "", "OpenStack farm label (A/B/C/D)")
	f.StringVar(&a.FarmVIP, "farm-vip", "", "farm external VIP")
	f.StringVar(&a.Rack, "rack", "", "rack position, e.g. R1/37U-38U")
	f.StringVar(&a.Location, "location", "", "physical location")
	f.StringVar(&a.WGTunnel, "wg", "", "WireGuard tunnel (wg0/wg1/wg2/wg3)")
	f.StringVar(&a.Status, "status", "", "active | broken | reserved (default active)")
	f.StringVar(&a.Note, "note", "", "free-form note")
	return gate(cmd, "ip", classMutate)
}

// ipRmCmd deletes one allocation. Mutate (default-deny w/o grant).
func ipRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm <ip>",
		Aliases: []string{"delete"},
		Short:   "Remove an IP allocation",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid IP: %q", ip)
			}
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.IPAllocDelete(cmd.Context(), ip); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "removed %s", ip)
				return nil
			})
		},
	}
	return gate(cmd, "ip", classMutate)
}

func joinKinds() string { return strings.Join(ipKinds, "|") }

// ipKindLabels are friendly group headers for the ledger listing.
var ipKindLabels = map[string]string{
	"personal":    "Personal device",
	"server":      "Physical server",
	"vm":          "OpenStack VM",
	"floating-ip": "Floating IP",
	"router-gw":   "Router GW",
	"dnat-vip":    "DNAT VIP",
}

// renderIPAllocations prints the ledger grouped by kind, mirroring `vctl list`:
// an accented group header, columns aligned across all rows, muted secondary
// fields, and a leading state dot (active/reserved/broken).
func renderIPAllocations(w io.Writer, rows []store.IPAllocation) {
	// Bucket rows by kind, preserving the store's IP-sorted order within each.
	byKind := map[string][]store.IPAllocation{}
	for _, a := range rows {
		byKind[a.Kind] = append(byKind[a.Kind], a)
	}

	// Build display cells for every row and compute column widths across ALL
	// rows so every group stays aligned. Columns: ip, owner, label, context, farm, wg.
	dot := make([]string, len(rows))
	cells := make([][]string, len(rows))
	note := make([]string, len(rows))
	idx := map[string]int{}
	widths := make([]int, 6)
	pos := 0
	order := append([]string{}, ipKinds...)
	for _, kind := range order {
		for _, a := range byKind[kind] {
			label := ui.Truncate(a.Label, 40)
			switch a.Status {
			case "broken":
				label = ui.Fail(label)
			case "reserved":
				label = ui.Muted(label)
			default:
				label = ui.Value(label)
			}
			c := []string{
				a.IP,
				orDashMuted(a.Owner),
				label,
				ui.Muted(ui.Truncate(firstNonEmpty(a.Project, a.Rack, a.OS), 30)),
				orDashMuted(a.Farm),
				ipWGCell(a.WGTunnel),
			}
			for j := range c {
				if n := lipgloss.Width(c[j]); n > widths[j] {
					widths[j] = n
				}
			}
			dot[pos] = ui.Dot(ipStatusState(a.Status))
			cells[pos] = c
			note[pos] = ui.Muted(a.Note)
			idx[a.IP] = pos
			pos++
		}
	}

	groupStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	for _, kind := range order {
		grp := byKind[kind]
		if len(grp) == 0 {
			continue
		}
		name := ipKindLabels[kind]
		if name == "" {
			name = kind
		}
		fmt.Fprintf(w, "%s %s\n", groupStyle.Render("▌ "+name), ui.Muted(fmt.Sprintf("· %d", len(grp))))
		for _, a := range grp {
			i := idx[a.IP]
			var line strings.Builder
			line.WriteString("  ")
			line.WriteString(dot[i])
			line.WriteString(" ")
			for j, c := range cells[i] {
				if j > 0 {
					line.WriteString("  ")
				}
				line.WriteString(ui.PadRight(c, widths[j]))
			}
			if n := note[i]; lipgloss.Width(n) > 0 {
				line.WriteString("  ")
				line.WriteString(n)
			}
			fmt.Fprintln(w, strings.TrimRight(line.String(), " "))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, ui.Muted(fmt.Sprintf("%d addresses", len(rows))))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// orDashMuted renders a muted '-' for an empty cell, otherwise the value.
func orDashMuted(s string) string {
	if s == "" {
		return ui.Muted("-")
	}
	return s
}

// ipWGCell renders the WireGuard tunnel tag, or a muted dash when none.
func ipWGCell(wg string) string {
	if wg == "" {
		return ui.Muted("-")
	}
	return ui.Value(wg)
}

// ipStatusState maps an allocation status to a UI dot state.
func ipStatusState(status string) ui.State {
	switch status {
	case "broken":
		return ui.StateFail
	case "reserved":
		return ui.StateWarn
	default:
		return ui.StateOK
	}
}
