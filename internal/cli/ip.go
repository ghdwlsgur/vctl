package cli

import (
	"fmt"
	"net"
	"os"
	"slices"

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
				out := make([][]string, 0, len(rows))
				for _, a := range rows {
					out = append(out, []string{
						a.IP,
						muted(a.Owner),
						a.Kind,
						ui.Truncate(a.Label, 34),
						muted(a.Project),
						muted(a.Farm),
						muted(a.WGTunnel),
						muted(a.Note),
					})
				}
				ui.Section(os.Stdout, fmt.Sprintf("ip allocations (%d)", len(rows)))
				return ui.Table(os.Stdout, []string{"ip", "owner", "kind", "label", "project", "farm", "wg", "note"}, out)
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

func joinKinds() string {
	out := ""
	for i, k := range ipKinds {
		if i > 0 {
			out += "|"
		}
		out += k
	}
	return out
}

// muted renders '-' for an empty cell, otherwise the value.
func muted(s string) string {
	if s == "" {
		return ui.Muted("-")
	}
	return s
}
