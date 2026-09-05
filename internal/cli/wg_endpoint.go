package cli

import (
	"fmt"
	"net"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

var wgEndpointKinds = []string{"vm", "physical-host", "device", "gateway"}

func wgEndpointCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endpoint",
		Short: "Manage endpoint identity and VM-to-physical-host placement",
		Long: `endpoint attaches a stable identity to a WireGuard public key.
For VM endpoints, --parent records the physical inventory host that runs the
VM, allowing 'wg serve' to draw the endpoint together with its host network.`,
	}
	cmd.AddCommand(wgEndpointListCmd(env), wgEndpointSetCmd(env), wgEndpointRmCmd(env))
	return cmd
}

func wgEndpointListCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List endpoint annotations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				items, err := st.WGEndpointAnnotations(cmd.Context())
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(items))
				for _, a := range items {
					rows = append(rows, []string{
						wireguard.ShortKey(a.PublicKey), ui.OrDash(a.Label), a.Kind,
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
	return cmdkit.Gate(cmd, "wg")
}

func wgEndpointSetCmd(env cmdkit.Env) *cobra.Command {
	var a store.WGEndpointAnnotation
	cmd := &cobra.Command{
		Use:   "set <public-key>",
		Short: "Create or update an endpoint annotation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.PublicKey = args[0]
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				// Merge, do not replace. This used to write the flags as the whole
				// row, so `set <key> --inventory-host h` on an annotated endpoint
				// silently reset its kind to the flag default and blanked its
				// note. Only the flags given on this invocation change anything.
				existing, err := st.WGEndpointAnnotations(cmd.Context())
				if err != nil {
					return err
				}
				var current *store.WGEndpointAnnotation
				for i := range existing {
					if existing[i].PublicKey == a.PublicKey {
						current = &existing[i]
						break
					}
				}
				merged := mergeEndpointAnnotation(current, a, cmd.Flags().Changed)
				if err := validateEndpointAnnotation(merged); err != nil {
					return err
				}
				if err := st.WGEndpointAnnotationUpsert(cmd.Context(), merged); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "saved WireGuard endpoint %s", wireguard.ShortKey(merged.PublicKey))
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
	return cmdkit.Gate(cmd, "wg-sync")
}

func wgEndpointRmCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm <public-key>",
		Aliases: []string{"delete"},
		Short:   "Remove an endpoint annotation",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.WGEndpointAnnotationDelete(cmd.Context(), args[0]); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "removed WireGuard endpoint %s", wireguard.ShortKey(args[0]))
				return nil
			})
		},
	}
	return cmdkit.Gate(cmd, "wg-sync")
}

// mergeEndpointAnnotation lays the flags given on this invocation over the row
// already stored. A flag that was not passed keeps the stored value; a flag
// passed as empty clears it. With no stored row the flags are the row, defaults
// included.
func mergeEndpointAnnotation(current *store.WGEndpointAnnotation, flags store.WGEndpointAnnotation, changed func(string) bool) store.WGEndpointAnnotation {
	if current == nil {
		return flags
	}
	out := *current
	out.PublicKey = flags.PublicKey
	for _, f := range []struct {
		name string
		dst  *string
		src  string
	}{
		{"label", &out.Label, flags.Label},
		{"kind", &out.Kind, flags.Kind},
		{"underlay-ip", &out.UnderlayIP, flags.UnderlayIP},
		{"tunnel-ip", &out.TunnelIP, flags.TunnelIP},
		{"site", &out.Site, flags.Site},
		{"inventory-host", &out.InventoryHost, flags.InventoryHost},
		{"parent", &out.ParentHostname, flags.ParentHostname},
		{"note", &out.Note, flags.Note},
	} {
		if changed(f.name) {
			*f.dst = f.src
		}
	}
	return out
}

func validateEndpointAnnotation(a store.WGEndpointAnnotation) error {
	if !slices.Contains(wgEndpointKinds, a.Kind) {
		return fmt.Errorf("--kind must be one of: vm|physical-host|device|gateway")
	}
	if a.UnderlayIP != "" && net.ParseIP(a.UnderlayIP) == nil {
		return fmt.Errorf("invalid --underlay-ip: %q", a.UnderlayIP)
	}
	if a.TunnelIP != "" && net.ParseIP(a.TunnelIP) == nil {
		return fmt.Errorf("invalid --tunnel-ip: %q", a.TunnelIP)
	}
	return nil
}
