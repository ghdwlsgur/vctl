package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstackapi"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// openstackFarmDoctorCmd answers "why is this deployment not settling" before
// somebody has to read a reconcile log to find out.
//
// A reconcile that fails says one thing: the control plane could not be asked.
// Which of five reasons that was — no credentials filed, a stored auth_url
// nobody can reach, TLS that will not verify, a token without the scope to list
// services, a listing that stops partway — is the part that takes the time, and
// it is the same five every time.
//
// # Read-only, on both sides
//
// Every OpenStack call here is a GET behind an auth POST. Nothing touches
// membership, the VM snapshot or the run history: a command somebody reaches
// for when a farm is already misbehaving must not be able to make it worse, and
// "diagnostic" is exactly the word people use for the tool they run without
// thinking about what it writes.
func openstackFarmDoctorCmd(env CommandEnv) *cobra.Command {
	var insecure bool
	cmd := &cobra.Command{
		Use:   "doctor [deployment]",
		Short: "Check what a reconcile would need, without changing anything",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.withStore(cmd.Context(), false, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, err := farmChoices(ctx, st)
				if err != nil {
					return err
				}
				if len(farms) == 0 {
					ui.Warnf(os.Stderr, "no deployments yet. Run the node agents, then 'vctl openstack'.")
					return nil
				}
				var pick farmChoice
				if len(args) > 0 {
					if pick, err = resolveFarm(farms, args[0]); err != nil {
						return err
					}
				} else {
					if !isTerminal() {
						return fmt.Errorf("a deployment is required when there is no terminal to pick at")
					}
					i, err := pickIndex(farmPickLabels(farms), nil, "Check a deployment")
					if err != nil {
						return err
					}
					pick = farms[i]
				}
				checks := diagnoseFarm(ctx, a, st, pick.ID, insecure)
				renderFarmDoctor(os.Stdout, pick, checks)
				for _, c := range checks {
					if c.State == ui.StateFail {
						return fmt.Errorf("%s: %d check(s) failed", pick.ID, countFailed(checks))
					}
				}
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification, to tell a certificate problem from a reachability one")
	return cmd
}

// farmCheck is one question and what came back.
type farmCheck struct {
	Name   string
	State  ui.State
	Detail string
}

func countFailed(cs []farmCheck) int {
	var n int
	for _, c := range cs {
		if c.State == ui.StateFail {
			n++
		}
	}
	return n
}

// diagnoseFarm asks, in the order a failure cascades: nothing below a failed
// check can be answered, so each one says why the rest are missing rather than
// repeating the same error five times.
func diagnoseFarm(ctx context.Context, a *app.App, st *store.Store, id string, insecure bool) []farmCheck {
	var out []farmCheck
	add := func(name string, state ui.State, format string, args ...any) {
		out = append(out, farmCheck{Name: name, State: state, Detail: oneLine(fmt.Sprintf(format, args...))})
	}

	creds, err := vaultCredentials{app: a}.ForFarm(ctx, id)
	if err != nil {
		add("Credentials", ui.StateFail, "%v", err)
		add("Keystone", ui.StateWarn, "not attempted — there is nothing to authenticate with")
		return append(out, lastReconcileCheck(ctx, st, id))
	}
	missing := missingCredFields(creds)
	if len(missing) > 0 {
		add("Credentials", ui.StateWarn, "found, but %s not set", strings.Join(missing, " and "))
	} else {
		add("Credentials", ui.StateOK, "%s at %s", creds.Username, creds.AuthURL)
	}

	client, authErr := openstackapi.New(ctx, creds, insecure, farmDoctorTimeout)
	if authErr != nil {
		// A TLS failure and an unreachable endpoint read the same in the error,
		// and they call for completely different next steps. Ask again without
		// verification to tell them apart — only to report, never to proceed.
		if !insecure {
			if _, retry := openstackapi.New(ctx, creds, true, farmDoctorTimeout); retry == nil {
				add("Keystone", ui.StateFail,
					"authenticates only with TLS verification off — the certificate is the problem, not the route (%v)", authErr)
				return append(out, lastReconcileCheck(ctx, st, id))
			}
		}
		add("Keystone", ui.StateFail, "%v", authErr)
		return append(out, lastReconcileCheck(ctx, st, id))
	}
	verified := "verified TLS"
	if insecure {
		verified = "TLS verification skipped"
	}
	add("Keystone", ui.StateOK, "authenticated, %s", verified)

	// os-services and os-hypervisors are separate permissions and separate
	// failures: without services no controller is listed, without hypervisors a
	// compute node whose nova-compute is down disappears.
	svcs, svcErr := client.Services(ctx)
	if svcErr != nil {
		add("Nova services", ui.StateFail, "%v — controllers would not be listed", svcErr)
	} else {
		add("Nova services", ui.StateOK, "%d", len(svcs))
	}
	hyps, hypErr := client.Hypervisors(ctx)
	if hypErr != nil {
		add("Nova hypervisors", ui.StateFail, "%v — stopped compute nodes would not be listed", hypErr)
	} else {
		add("Nova hypervisors", ui.StateOK, "%d", len(hyps))
	}

	vms, vmErr := client.Instances(ctx)
	switch {
	case vmErr != nil && len(vms) > 0:
		// The listing stopped partway. Storing that is safe now, but it is the
		// state where a farm's VM count silently stops being the whole picture.
		add("Instances", ui.StateWarn, "%d listed, then stopped: %v", len(vms), vmErr)
	case vmErr != nil:
		add("Instances", ui.StateFail, "%v", vmErr)
	default:
		add("Instances", ui.StateOK, "%d, listing complete", len(vms))
	}

	if _, err := client.ProjectNames(ctx); err != nil {
		// Not fatal: the reconciler stores uuids and leaves the name column
		// alone rather than blanking what an earlier run found.
		add("Project names", ui.StateWarn, "%v — VMs would be listed by project uuid", err)
	} else {
		add("Project names", ui.StateOK, "resolvable")
	}

	return append(out, lastReconcileCheck(ctx, st, id))
}

// farmDoctorTimeout bounds each call. Shorter than the reconciler's, because
// somebody is waiting at a terminal for an answer about why something is slow.
const farmDoctorTimeout = 30 * time.Second

func missingCredFields(c openstackapi.Credentials) []string {
	var out []string
	for _, f := range []struct{ name, v string }{
		{"auth_url", c.AuthURL}, {"username", c.Username},
		{"password", c.Password}, {"project_name", c.ProjectName},
	} {
		if f.v == "" {
			out = append(out, f.name)
		}
	}
	return out
}

// lastReconcileCheck reads what the run history already knows, so the checks
// above can be compared against what actually happened.
func lastReconcileCheck(ctx context.Context, st *store.Store, id string) farmCheck {
	runs, err := st.ReconcileRuns(ctx)
	if err != nil {
		return farmCheck{Name: "Last reconcile", State: ui.StateWarn, Detail: err.Error()}
	}
	r, ok := runs[id]
	if !ok {
		return farmCheck{Name: "Last reconcile", State: ui.StateWarn, Detail: "never run"}
	}
	switch {
	case r.SucceededAt == nil:
		return farmCheck{Name: "Last reconcile", State: ui.StateFail,
			Detail: "never succeeded — " + orNone(r.LastError)}
	case r.LastError != "":
		return farmCheck{Name: "Last reconcile", State: ui.StateWarn,
			Detail: fmt.Sprintf("succeeded %s ago, failing since: %s",
				ui.CompactDuration(time.Since(*r.SucceededAt)), r.LastError)}
	default:
		return farmCheck{Name: "Last reconcile", State: ui.StateOK,
			Detail: ui.CompactDuration(time.Since(*r.SucceededAt)) + " ago"}
	}
}

func orNone(s string) string {
	if s == "" {
		return "no reason recorded"
	}
	return s
}

func renderFarmDoctor(w io.Writer, pick farmChoice, checks []farmCheck) {
	title := pick.ID
	if pick.Name != "" {
		title = pick.Name + " · " + pick.ID
	}
	ui.Section(w, title)
	rows := make([]ui.KV, 0, len(checks))
	for _, c := range checks {
		rows = append(rows, ui.KV{Key: c.Name, Value: c.Detail, State: c.State})
	}
	ui.KVs(w, rows)
}

// oneLine flattens an error for a table row.
//
// Vault and the OpenStack SDK return errors several lines long — a URL, a
// status, a bulleted cause — and dropping one into a key/value row breaks the
// alignment for every row after it. The whole message is kept, on one line,
// because the useful part is usually the last clause.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
