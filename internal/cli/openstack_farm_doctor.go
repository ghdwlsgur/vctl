package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstack/doctor"
	"github.com/ghdwlsgur/vctl/internal/openstack/farmcreds"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// openstackFarmDoctorCmd wires `farm doctor`: pick the deployment, run the
// diagnosis (internal/openstack/doctor, where it can be tested without a
// terminal, a Vault and a live control plane), and render or export it.
func openstackFarmDoctorCmd(env CommandEnv) *cobra.Command {
	var insecure bool
	var asJSON bool
	cmd := &cobra.Command{
		Use:               "doctor [deployment]",
		Short:             "Check what a reconcile would need, without changing anything",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: byPosition(completeFarm(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandOutput(cmd, asJSON)
			if err != nil {
				return err
			}
			return env.withStore(cmd.Context(), false, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, ok, err := farmChoicesForPick(ctx, a, st)
				if err != nil || !ok {
					return err
				}
				pick, err := pickFarm(farms, firstArg(args), "Check a deployment")
				if err != nil {
					return err
				}
				d := doctor.Doctor{
					Creds: farmcreds.Store{KV: a.Vault, Prefix: a.Cfg.VaultFarmPrefix},
					Runs:  st,
				}
				checks := d.Diagnose(ctx, pick.ID, insecure)
				if format != outputTable {
					if err := writeStructured(format, farmDoctorExport{
						Farm: pick.ID, Name: pick.Name, Checks: checks,
					}); err != nil {
						return err
					}
				} else {
					renderFarmDoctor(os.Stdout, pick, checks)
				}
				if n := doctor.Failed(checks); n > 0 {
					return fmt.Errorf("%s: %d check(s) failed", pick.ID, n)
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification, to tell a certificate problem from a reachability one")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (for dataset/agent export)")
	return supportsStructuredOutput(cmd)
}

// farmDoctorExport is the wire shape: the deployment the checks are about,
// then the checks in the order the diagnosis asked them.
type farmDoctorExport struct {
	Farm   string         `json:"farm"`
	Name   string         `json:"name,omitempty"`
	Checks []doctor.Check `json:"checks"`
}

// severityState maps the diagnosis's word onto the terminal's palette — the
// one place the two vocabularies meet.
func severityState(s doctor.Severity) ui.State {
	switch s {
	case doctor.OK:
		return ui.StateOK
	case doctor.Fail:
		return ui.StateFail
	default:
		return ui.StateWarn
	}
}

func renderFarmDoctor(w io.Writer, pick farmChoice, checks []doctor.Check) {
	title := pick.ID
	if pick.Name != "" {
		title = pick.Name + " · " + pick.ID
	}
	ui.Section(w, title)
	rows := make([]ui.KV, 0, len(checks))
	for _, c := range checks {
		rows = append(rows, ui.KV{Key: c.Name, Value: c.Detail, State: severityState(c.Severity)})
	}
	ui.KVs(w, rows)
}
