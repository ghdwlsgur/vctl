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

var wgEndpointKinds = []string{"vm", "physical-host", "device", "gateway"}

func wgEndpointCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endpoint",
		Short: "Manage endpoint identity and VM-to-physical-host placement",
		Long: `endpoint attaches a stable identity to a WireGuard public key.
For VM endpoints, --parent records the physical inventory host that runs the
VM, allowing 'wg serve' to draw the endpoint together with its host network.`,
	}
	cmd.AddCommand(wgEndpointListCmd(), wgEndpointSetCmd(), wgEndpointRmCmd())
	return cmd
}

func wgEndpointListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List endpoint annotations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				items, err := st.WGEndpointAnnotations(cmd.Context())
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(items))
				for _, a := range items {
					rows = append(rows, []string{
						shortKey(a.PublicKey), ui.OrDash(a.Label), a.Kind,
						ui.OrDash(a.UnderlayIP), ui.OrDash(a.TunnelIP),
						ui.OrDash(a.ParentHostname), ui.OrDash(a.Site),
					})
				}
				return ui.Table(os.Stdout,
					[]string{"public key", "endpoint", "kind", "underlay", "tunnel", "physical host", "site"},
					rows)
			})
		},
	}
	return gate(cmd, "wg", classRead)
}

func wgEndpointSetCmd() *cobra.Command {
	var a store.WGEndpointAnnotation
	cmd := &cobra.Command{
		Use:   "set <public-key>",
		Short: "Create or update an endpoint annotation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !slices.Contains(wgEndpointKinds, a.Kind) {
				return fmt.Errorf("--kind must be one of: vm|physical-host|device|gateway")
			}
			if a.UnderlayIP != "" && net.ParseIP(a.UnderlayIP) == nil {
				return fmt.Errorf("invalid --underlay-ip: %q", a.UnderlayIP)
			}
			if a.TunnelIP != "" && net.ParseIP(a.TunnelIP) == nil {
				return fmt.Errorf("invalid --tunnel-ip: %q", a.TunnelIP)
			}
			a.PublicKey = args[0]
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.WGEndpointAnnotationUpsert(cmd.Context(), a); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "saved WireGuard endpoint %s", shortKey(a.PublicKey))
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&a.Label, "label", "", "human endpoint name")
	f.StringVar(&a.Kind, "kind", "device", "vm | physical-host | device | gateway")
	f.StringVar(&a.UnderlayIP, "underlay-ip", "", "host/vNIC IP used for host-network placement")
	f.StringVar(&a.TunnelIP, "tunnel-ip", "", "WireGuard overlay IP (display only)")
	f.StringVar(&a.Site, "site", "", "site label used when no parent inventory host exists")
	f.StringVar(&a.InventoryHost, "inventory-host", "", "linked servers.hostname for the endpoint")
	f.StringVar(&a.ParentHostname, "parent", "", "physical servers.hostname that runs this VM")
	f.StringVar(&a.Note, "note", "", "operator note")
	return gate(cmd, "wg-sync", classMutate)
}

func wgEndpointRmCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm <public-key>",
		Aliases: []string{"delete"},
		Short:   "Remove an endpoint annotation",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.WGEndpointAnnotationDelete(cmd.Context(), args[0]); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "removed WireGuard endpoint %s", shortKey(args[0]))
				return nil
			})
		},
	}
	return gate(cmd, "wg-sync", classMutate)
}
