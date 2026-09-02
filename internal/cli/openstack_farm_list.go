package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// openstackFarmListCmd answers "which deployments are there, and is anything
// wrong with them".
//
// `vctl openstack list` answers a different question — which hosts run OpenStack —
// and reading a fleet's deployments off it means counting group headers. The
// farm command had no list at all, so `vctl openstack farm` printed help and
// the way to see the deployments was to look at something else.
//
// One line per farm, and the line says whether it is being kept up: the last
// successful reconcile is what makes every other number on the row worth
// trusting.
func openstackFarmListCmd(env cmdkit.Env) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Every deployment, with how recently anything confirmed it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := cmdkit.CommandOutput(cmd, asJSON)
			if err != nil {
				return err
			}
			return env.WithApp(func(a *app.App) error {
				ctx := cmd.Context()
				st := &openLater{app: a}
				defer st.Close()
				rows, err := farmSummaries(ctx, a, st, mustBeLive(cmd, format != cmdkit.OutputTable))
				if err != nil {
					return err
				}
				if format != cmdkit.OutputTable {
					return cmdkit.WriteStructured(format, rows)
				}
				return renderFarmList(os.Stdout, rows, time.Now())
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmdkit.SupportsStructuredOutput(cmd)
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

// farmSummaries is the catalog rendered as one row per deployment.
//
// It used to open four reads of its own and re-derive which hosts count towards
// a farm — the fourth copy of that rule. The rule now has one home and this is
// a projection of it, so the row and every other screen cannot disagree about
// what a deployment contains.
func farmSummaries(ctx context.Context, a *app.App, st *openLater, live bool) ([]farmSummary, error) {
	// The full reading: this row carries the last reconcile and a VM count,
	// and both come from it. It read the same four things separately before.
	//
	// Every column here turns over slowly — a reconcile runs every six hours and
	// a deployment gains a host on the timescale of somebody racking one — so a
	// stored reading inside the fresh window is not a lesser answer to this
	// question, it is the same one.
	rd, err := listingReading(ctx, a, st, fleet.ShapeFarms, live, fleetSnapshot)
	if err != nil {
		return nil, err
	}
	return summarize(rd.Catalog), nil
}

func summarize(cat fleet.Catalog) []farmSummary {
	out := make([]farmSummary, 0, len(cat.Farms()))
	for _, f := range cat.Farms() {
		row := farmSummary{
			ID: f.ID, Name: f.Name, Region: f.Region, State: f.State,
			Hosts: len(f.Hosts), VMs: cat.VMCount(f.ID), Unsettled: f.Unsettled,
		}
		// A deployment nothing has declared reads as active, the same way a
		// server row written before the column existed does.
		if row.State == "" {
			row.State = store.StateActive
		}
		if run := cat.Run(f.ID); run != nil {
			row.Reconciled, row.LastError = run.SucceededAt, run.LastError
		}
		out = append(out, row)
	}
	return out
}

func renderFarmList(w io.Writer, rows []farmSummary, now time.Time) error {
	return renderFarmListWidth(w, rows, now, 0)
}

func renderFarmListWidth(w io.Writer, rows []farmSummary, now time.Time, width int) error {
	if len(rows) == 0 {
		ui.Infof(w, "no deployments yet. Run the node agents, then 'vctl openstack'.")
		return nil
	}
	cells := make([][]string, 0, len(rows))
	for _, f := range rows {
		name := f.Name
		if name == "" {
			name = ui.Muted("(unnamed)")
		}
		cells = append(cells, []string{
			name,
			ui.Muted(f.ID),
			ui.Muted(f.Region),
			cmdkit.StateCell(f.State),
			fmt.Sprintf("%d", f.Hosts),
			fmt.Sprintf("%d", f.VMs),
			farmReconciledCell(f, now),
			farmListNote(f),
		})
	}
	columns := []ui.Column{
		{Header: "name", MinWidth: 14, MaxWidth: 28},
		{Header: "endpoint", MinWidth: 14, MaxWidth: 24, Optional: true, Priority: 3},
		{Header: "region", MinWidth: 6, MaxWidth: 12, Optional: true, Priority: 4},
		{Header: "state", MinWidth: 5, MaxWidth: 8},
		{Header: "hosts", MinWidth: 5, MaxWidth: 5, AlignRight: true},
		{Header: "vms", MinWidth: 3, MaxWidth: 4, AlignRight: true},
		{Header: "reconciled", MinWidth: 10, MaxWidth: 10},
		{Header: "note", MinWidth: 12, MaxWidth: 44, Optional: true, Priority: 2},
	}
	return ui.ResponsiveTable(w, columns, cells, ui.TableOptions{Width: width, Indent: "  "})
}

// farmReconciledCell says when membership was last settled, which is what makes
// the host and VM counts beside it worth reading.
func farmReconciledCell(f farmSummary, now time.Time) string {
	if f.Reconciled == nil {
		return ui.Warn("never")
	}
	age := now.Sub(*f.Reconciled)
	s := strutil.CompactDuration(age) + " ago"
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
