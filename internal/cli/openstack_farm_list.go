package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// openstackFarmListCmd answers "which deployments are there, and is anything
// wrong with them".
//
// `vctl openstack` answers a different question — which hosts run OpenStack —
// and reading a fleet's deployments off it means counting group headers. The
// farm command had no list at all, so `vctl openstack farm` printed help and
// the way to see the deployments was to look at something else.
//
// One line per farm, and the line says whether it is being kept up: the last
// successful reconcile is what makes every other number on the row worth
// trusting.
func openstackFarmListCmd(env CommandEnv) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Every deployment, with how recently anything confirmed it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				rows, err := farmSummaries(ctx, st, time.Now())
				if err != nil {
					return err
				}
				if asJSON {
					return writeJSON(rows)
				}
				renderFarmList(os.Stdout, rows, time.Now())
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmd
}

// farmSummary is one deployment as an operator scans it.
type farmSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Region string `json:"region,omitempty"`
	State  string `json:"state"`
	Hosts  int    `json:"hosts"`
	VMs    int    `json:"vms"`

	// Reconciled is the last run that settled membership. Nil when nothing ever
	// has, which is a different thing from an old one and reads differently.
	Reconciled *time.Time `json:"reconciled_at,omitempty"`
	// LastError is why the most recent attempt did not settle it.
	LastError string `json:"last_error,omitempty"`
	// Unsettled counts hosts the probe put here that no control plane has
	// confirmed.
	Unsettled int `json:"unsettled"`
}

func farmSummaries(ctx context.Context, st *store.Store, now time.Time) ([]farmSummary, error) {
	hosts, err := st.OpenStackHosts(ctx)
	if err != nil {
		return nil, err
	}
	deps, err := st.Deployments(ctx)
	if err != nil {
		return nil, err
	}
	runs, err := st.ReconcileRuns(ctx)
	if err != nil {
		return nil, err
	}
	vms, err := st.Instances(ctx, store.InstanceFilter{})
	if err != nil {
		return nil, err
	}

	byID := map[string]*farmSummary{}
	for _, d := range deps {
		byID[d.ID] = &farmSummary{ID: d.ID, Name: d.DisplayName, Region: d.Region, State: d.State}
	}
	for _, h := range hosts {
		if h.Farm == "" || !h.Detected {
			continue
		}
		f, ok := byID[h.Farm]
		if !ok {
			// A deployment nobody has named is still a deployment, and leaving
			// it out would make the listing disagree with `vctl openstack`.
			f = &farmSummary{ID: h.Farm, State: store.StateActive}
			byID[h.Farm] = f
		}
		f.Hosts++
		if h.Confidence == store.ConfidenceLocalOnly {
			f.Unsettled++
		}
	}
	for _, v := range vms {
		if f, ok := byID[v.DeploymentID]; ok {
			f.VMs++
		}
	}
	for id, r := range runs {
		f, ok := byID[id]
		if !ok {
			continue
		}
		f.Reconciled = r.SucceededAt
		f.LastError = r.LastError
	}

	out := make([]farmSummary, 0, len(byID))
	for _, f := range byID {
		out = append(out, *f)
	}
	// By what is printed, so the order on screen looks like an order.
	sort.Slice(out, func(i, j int) bool { return farmSortKey(out[i]) < farmSortKey(out[j]) })
	return out, nil
}

func farmSortKey(f farmSummary) string {
	if f.Name != "" {
		return f.Name
	}
	return f.ID
}

func renderFarmList(w io.Writer, rows []farmSummary, now time.Time) {
	if len(rows) == 0 {
		ui.Infof(w, "no deployments yet. Run the node agents, then 'vctl openstack'.")
		return
	}
	cells := [][]string{{
		ui.Muted("NAME"), ui.Muted("ENDPOINT"), ui.Muted("REGION"), ui.Muted("STATE"),
		ui.Muted("HOSTS"), ui.Muted("VMS"), ui.Muted("RECONCILED"), "",
	}}
	for _, f := range rows {
		name := f.Name
		if name == "" {
			name = ui.Muted("(unnamed)")
		}
		cells = append(cells, []string{
			name,
			ui.Muted(f.ID),
			ui.Muted(f.Region),
			stateCell(f.State),
			fmt.Sprintf("%d", f.Hosts),
			fmt.Sprintf("%d", f.VMs),
			farmReconciledCell(f, now),
			farmListNote(f),
		})
	}
	widths := ui.ColumnWidths(cells)
	for i := range cells {
		line := "  "
		for j, c := range cells[i] {
			if j > 0 {
				line += "  "
			}
			line += ui.PadRight(c, widths[j])
		}
		fmt.Fprintln(w, trimTrailing(line))
	}
}

// farmReconciledCell says when membership was last settled, which is what makes
// the host and VM counts beside it worth reading.
func farmReconciledCell(f farmSummary, now time.Time) string {
	if f.Reconciled == nil {
		return ui.Warn("never")
	}
	age := now.Sub(*f.Reconciled)
	s := ui.CompactDuration(age) + " ago"
	if age > farmStaleWindow {
		return ui.Warn(s)
	}
	return ui.Muted(s)
}

func farmListNote(f farmSummary) string {
	switch {
	case f.LastError != "":
		return ui.Fail("failing: " + ui.Truncate(f.LastError, 44))
	case f.Unsettled > 0:
		return ui.Warn(fmt.Sprintf("%d host(s) unsettled", f.Unsettled))
	default:
		return ""
	}
}

func trimTrailing(s string) string {
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}
