package cli

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func wgRelationCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "relation",
		Short: "Declare typed relations between entities",
		Long: `relation connects two declared entities with a typed, directed edge.

  placed-on    vm         -> physical-host   runtime placement
  member-of    host|farm  -> farm|site       static membership
  attached-to  tunnel|vm  -> network         which fabric an interface sits on
  transits     tunnel     -> edge|egress     the underlay a tunnel rides (attrs.order)
  carries      tunnel     -> network         attrs.method: direct | proxy | dnat

Paths and failure domains are derived by walking these, never stored.`,
	}
	cmd.AddCommand(wgRelationListCmd(env), wgRelationSetCmd(env), wgRelationRmCmd(env))
	return cmd
}

func wgRelationListCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List declared relations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				items, err := st.NetRelations(cmd.Context())
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(items))
				for _, r := range items {
					rows = append(rows, []string{r.SrcID, r.Kind, r.DstID, attrsSummary(r.Attrs)})
				}
				return ui.Table(os.Stdout, []string{"source", "relation", "target", "attrs"}, rows)
			})
		},
	}
	return cmdkit.Gate(cmd, "wg")
}

func wgRelationSetCmd(env cmdkit.Env) *cobra.Command {
	var note string
	var attrKV []string
	var attrsJSON string
	cmd := &cobra.Command{
		Use:   "set <src-id> <kind> <dst-id>",
		Short: "Create or update a relation",
		Long: `Both endpoints must already be declared with 'wg entity set'; a relation to
an undeclared entity is rejected rather than left dangling.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			rel := store.NetRelation{SrcID: args[0], Kind: args[1], DstID: args[2], Note: note}
			if !slices.Contains(store.NetRelationKinds, rel.Kind) {
				return fmt.Errorf("relation kind must be one of: %s", strings.Join(store.NetRelationKinds, "|"))
			}
			attrs, err := parseAttrs(attrKV, attrsJSON)
			if err != nil {
				return err
			}
			rel.Attrs = attrs
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.NetRelationUpsert(cmd.Context(), rel); err != nil {
					return fmt.Errorf("saving relation (are both entities declared?): %w", err)
				}
				ui.Successf(os.Stdout, "saved %s %s %s", rel.SrcID, rel.Kind, rel.DstID)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&attrKV, "attr", nil, "attribute as key=value (repeatable)")
	f.StringVar(&attrsJSON, "attrs-json", "", "attributes as a JSON object; wins over --attr")
	f.StringVar(&note, "note", "", "operator note")
	return cmdkit.Gate(cmd, "wg-sync")
}

func wgRelationRmCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm <src-id> <kind> <dst-id>",
		Aliases: []string{"delete"},
		Short:   "Remove one relation",
		Args:    cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.NetRelationDelete(cmd.Context(), args[0], args[2], args[1]); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "removed %s %s %s", args[0], args[1], args[2])
				return nil
			})
		},
	}
	return cmdkit.Gate(cmd, "wg-sync")
}
