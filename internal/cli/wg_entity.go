package cli

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// netEntityIDPrefix is the id prefix each kind must carry. Ids are how relations
// and the dashboard address an entity, so a readable, kind-revealing id is worth
// enforcing: `farm/x` cannot be declared as a vm by mistake.
var netEntityIDPrefix = map[string]string{
	"site": "site/", "farm": "farm/", "physical-host": "host/", "vm": "vm/",
	"network": "net/", "tunnel": "tunnel/", "edge": "edge/", "egress": "egress/",
}

// validateNetEntityID enforces the id shape. Networks additionally need the
// farm segment — `net/<farm>/<name>` — because one farm can hold several
// networks with the same CIDR and the name alone would not tell them apart.
func validateNetEntityID(kind, id string) error {
	prefix, ok := netEntityIDPrefix[kind]
	if !ok {
		return fmt.Errorf("--kind must be one of: %s", strings.Join(store.NetEntityKinds, "|"))
	}
	if !strings.HasPrefix(id, prefix) || len(id) == len(prefix) {
		return fmt.Errorf("id for kind %s must look like %s<name>", kind, prefix)
	}
	if kind == "network" {
		rest := strings.TrimPrefix(id, prefix)
		if farm, name, found := strings.Cut(rest, "/"); !found || farm == "" || name == "" {
			return fmt.Errorf("network id must be net/<farm>/<name> (got %q)", id)
		}
	}
	return nil
}

// parseAttrs turns repeated `--attr k=v` flags and an optional `--attrs-json`
// document into one map. Flags give strings; JSON is for anything structured
// (an oif list, a nested method spec) and wins on key collision so a document
// can correct a flag.
func parseAttrs(kv []string, doc string) (map[string]any, error) {
	attrs := map[string]any{}
	for _, item := range kv {
		k, v, found := strings.Cut(item, "=")
		if !found || k == "" {
			return nil, fmt.Errorf("--attr must be key=value (got %q)", item)
		}
		attrs[k] = v
	}
	if strings.TrimSpace(doc) != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(doc), &extra); err != nil {
			return nil, fmt.Errorf("--attrs-json: %w", err)
		}
		maps.Copy(attrs, extra)
	}
	return attrs, nil
}

// attrsSummary renders attrs on one table cell without drowning the listing.
func attrsSummary(attrs map[string]any) string {
	if len(attrs) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, attrs[k]))
	}
	return strings.Join(parts, " ")
}

func wgEntityCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "entity",
		Short: "Declare underlay and overlay entities the topology is drawn from",
		Long: `entity declares a site, farm, physical host, VM, network, tunnel, edge or
egress as a first-class object. Relations between entities ('wg relation') give
the dashboard the underlay under the tunnels and the patterns laid over them,
so a new farm or tunnel is a row, not a code change.

Ids carry their kind: site/<n>, farm/<n>, host/<n>, vm/<n>, tunnel/<n>,
edge/<n>, egress/<n>. Networks are net/<farm>/<name> — keyed by identity, not
CIDR, because one farm can hold several networks with the same CIDR.`,
	}
	cmd.AddCommand(wgEntityListCmd(env), wgEntitySetCmd(env), wgEntityRmCmd(env))
	return cmd
}

func wgEntityListCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List declared entities",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				items, err := st.NetEntities(cmd.Context())
				if err != nil {
					return err
				}
				rows := make([][]string, 0, len(items))
				for _, e := range items {
					rows = append(rows, []string{
						e.ID, e.Kind, ui.OrDash(e.Label), ui.OrDash(e.Site), attrsSummary(e.Attrs),
					})
				}
				return ui.Table(os.Stdout, []string{"id", "kind", "label", "site", "attrs"}, rows)
			})
		},
	}
	return cmdkit.Gate(cmd, "wg")
}

func wgEntitySetCmd(env cmdkit.Env) *cobra.Command {
	var e store.NetEntity
	var attrKV []string
	var attrsJSON string
	cmd := &cobra.Command{
		Use:   "set <id>",
		Short: "Create or update a declared entity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			e.ID = args[0]
			if err := validateNetEntityID(e.Kind, e.ID); err != nil {
				return err
			}
			attrs, err := parseAttrs(attrKV, attrsJSON)
			if err != nil {
				return err
			}
			e.Attrs = attrs
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.NetEntityUpsert(cmd.Context(), e); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "saved entity %s", e.ID)
				return nil
			})
		},
	}
	f := cmd.Flags()
	f.StringVar(&e.Kind, "kind", "", strings.Join(store.NetEntityKinds, " | "))
	f.StringVar(&e.Label, "label", "", "human name")
	f.StringVar(&e.Site, "site", "", "site label for grouping")
	f.StringArrayVar(&attrKV, "attr", nil, "kind-specific attribute as key=value (repeatable)")
	f.StringVar(&attrsJSON, "attrs-json", "", "kind-specific attributes as a JSON object; wins over --attr")
	f.StringVar(&e.Note, "note", "", "operator note")
	_ = cmd.MarkFlagRequired("kind")
	return cmdkit.Gate(cmd, "wg-sync")
}

func wgEntityRmCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm <id>",
		Aliases: []string{"delete"},
		Short:   "Remove a declared entity and every relation that references it",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.NetEntityDelete(cmd.Context(), args[0]); err != nil {
					return err
				}
				ui.Successf(os.Stdout, "removed entity %s (and its relations)", args[0])
				return nil
			})
		},
	}
	return cmdkit.Gate(cmd, "wg-sync")
}
