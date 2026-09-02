package openstack

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/openstack/farmcreds"
	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
	"github.com/ghdwlsgur/vctl/internal/openstack/reconcile"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// reconcileTimeout bounds one deployment's control-plane conversation. A farm
// whose Keystone is unreachable must not hold up the rest.
const reconcileTimeout = 60 * time.Second

// instanceTimeout bounds the VM listing, which pages and so takes longer than
// the two membership calls put together.
const instanceTimeout = 180 * time.Second

// ReconcileCmd is `openstack reconcile`, exported on its own because it is
// wired into both binaries: under this package's Cmd for operators, and under
// the agent root so a controller host can run it as a unit.
func ReconcileCmd(env cmdkit.Env) *cobra.Command {
	var (
		only           string
		self           bool
		hostname       string
		insecure       bool
		dryRun         bool
		asJSON         bool
		failOn         string
		includeRetired bool
	)
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Ask each deployment's control plane which hosts it owns, and confirm membership",
		// `vctl openstack reconcile seoul` used to reconcile every farm: the
		// argument went nowhere and the run looked like the one that was asked
		// for. The deployment goes in --farm.
		Args: cobra.NoArgs,
		Long: "The probe can only say a host points at a Keystone. Two deployments behind one proxy\n" +
			"look identical from a host, so that inference is recorded as local-only.\n\n" +
			"This asks nova which compute hosts each deployment actually owns and promotes the\n" +
			"hosts both sides agree on to confirmed. Disagreements are reported, not resolved.\n\n" +
			// The compiled default: help is rendered before any config is
			// loaded, and the path it teaches is the one an unconfigured
			// install uses. vault_farm_prefix moves the runtime read.
			"Credentials are read from Vault under " + config.Defaults().VaultFarmPrefix + "/vctl-<host_port>, at use time.",
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := cmdkit.CommandOutput(cmd, asJSON)
			if err != nil {
				return err
			}
			// The dedicated reconcile role, not the operator rw role. This
			// command's credential lives on farm controllers (vctl-reconciler
			// AppRole) and in the CronJob's policy — vctl-rw there meant every
			// controller's root could write the whole operator surface
			// (servers, rbac, ipam, wg). The reconcile role can touch exactly
			// what a reconcile writes: memberships, run history, control
			// hosts, and the VM snapshot.
			return env.WithPurposeStore(cmd.Context(), app.PurposeOpenStackReconcile, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, err := st.LocalOnlyFarms(ctx)
				if err != nil {
					return err
				}
				if len(farms) == 0 {
					ui.Warnf(os.Stderr, "no deployments to reconcile. Run the node agents first.")
					return nil
				}
				if self {
					id, err := farmOfHost(farms, hostname)
					if err != nil {
						return err
					}
					only = id
				}
				// Accept the name people gave the deployment, not just its
				// endpoint. `farm show` and `vm` both do, and a --farm that
				// takes one spelling in one command and another elsewhere is a
				// flag somebody has to remember the shape of.
				if only != "" {
					id, err := ResolveFarmID(ctx, a, st, only)
					if err != nil {
						return err
					}
					only = id
				}
				// A retired deployment is one somebody said is not operated any
				// more. Asking its control plane every run spends a credential
				// and a timeout on a farm nobody expects to answer, and files
				// the failure as news. Naming it explicitly still works — that
				// is somebody saying they mean this one.
				retired := map[string]bool{}
				if only == "" && !includeRetired {
					deps, err := st.Deployments(ctx)
					if err != nil {
						return err
					}
					for _, d := range deps {
						if d.State == store.StateRetired {
							retired[d.ID] = true
						}
					}
				}
				ids := make([]string, 0, len(farms))
				var skipped int
				for id := range farms {
					if only != "" && !strings.EqualFold(id, only) {
						continue
					}
					if retired[id] {
						skipped++
						continue
					}
					ids = append(ids, id)
				}
				if skipped > 0 && format == cmdkit.OutputTable {
					ui.Infof(os.Stderr, "skipping %d retired deployment(s); --include-retired to reconcile them", skipped)
				}
				sort.Strings(ids)
				if len(ids) == 0 {
					return fmt.Errorf("no deployment matches %q", only)
				}
				req := reconcile.Request{Insecure: insecure, DryRun: dryRun}
				for _, id := range ids {
					hosts := farms[id]
					sort.Strings(hosts)
					req.Farms = append(req.Farms, reconcile.Farm{ID: id, LocalHosts: hosts})
				}
				svc := &reconcile.Service{
					Creds: farmcreds.Store{KV: a.Vault, Prefix: a.Cfg.VaultFarmPrefix},
					Cloud: novaCloud{},
					Repo:  storeRepo{st: st},
				}
				want, err := parseFailOn(failOn)
				if err != nil {
					return err
				}
				startedAt := time.Now()
				if format == cmdkit.OutputTable {
					ui.Section(os.Stdout, "openstack reconcile")
				}
				rep, runErr := svc.Run(ctx, req)
				took := time.Since(startedAt)
				// A reconcile is the thing most likely to make a stored reading
				// wrong: it settles membership and replaces the VM rows. Dropped
				// even on a partial run, because "some of it changed" is not a
				// picture worth keeping.
				if !dryRun {
					forgetReadings(ctx, a, st)
				}
				if format != cmdkit.OutputTable {
					if err := cmdkit.WriteStructured(format, reconcileReportJSON(rep, startedAt, took, dryRun)); err != nil {
						return err
					}
				} else {
					// Rendered before the error is returned: a run that reached
					// nothing still has per-farm reasons worth reading.
					renderReconcile(rep, dryRun)
				}
				if runErr != nil {
					return runErr
				}
				// A run where one farm answered and seven did not is a success
				// by the old measure, and a timer cannot tell it from a healthy
				// one. What counts as failure is the caller's to say.
				if hit := rep.FailOn(want); len(hit) > 0 {
					names := make([]string, 0, len(hit))
					for _, p := range hit {
						names = append(names, string(p))
					}
					return fmt.Errorf("reconcile finished with %s; %d of %d deployments answered",
						strings.Join(names, ", "), rep.Reached, len(rep.Outcomes))
				}
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&only, "farm", "", "reconcile only this deployment")
	cmd.Flags().BoolVar(&self, "self", false, "reconcile only the deployment this host belongs to")
	cmd.Flags().StringVar(&hostname, "hostname", "", "inventory hostname for --self; defaults to the os hostname")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification against the control plane (self-signed endpoints)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change without writing")
	cmd.Flags().BoolVar(&includeRetired, "include-retired", false, "also reconcile deployments declared retired")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable result, for timers and dashboards")
	cmd.Flags().StringVar(&failOn, "fail-on", "",
		"exit non-zero when any of these occurred: unreachable, no-credentials, partial, warning")
	cmd.MarkFlagsMutuallyExclusive("self", "farm")
	cmdkit.RegisterCompletion(cmd, "farm", CompleteFarm(env))
	cmdkit.RegisterCompletion(cmd, "hostname", cmdkit.CompleteInventoryHost(env))
	// A closed set, and the only completion here that needs nothing from the
	// database: these four words are the contract.
	cmdkit.RegisterCompletion(cmd, "fail-on", cmdkit.StaticCompletions(
		"unreachable", "no-credentials", "partial", "warning"))
	return cmdkit.SupportsStructuredOutput(cmd)
}

// farmOfHost finds which deployment this machine belongs to.
//
// It exists so a unit file does not have to carry the farm's name. A host that
// is moved between deployments, or a farm whose Keystone VIP changes, would
// otherwise leave a stale identifier in a systemd unit that nobody looks at.
//
// The inventory name is not always the os hostname — one host in this fleet
// reports as k8s-all-01 while the inventory calls it sre-srv-0023 — so the name
// can be overridden the same way the node agent overrides it.
func farmOfHost(farms map[string][]string, hostname string) (string, error) {
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	if hostname == "" {
		return "", fmt.Errorf("--self needs a hostname and the os did not provide one; pass --hostname")
	}
	for id, hosts := range farms {
		for _, h := range hosts {
			if strings.EqualFold(h, hostname) {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("%s is not a member of any deployment the probe has reported; nothing to reconcile", hostname)
}

func reportReconcile(id string, r membership.Outcome, dry bool) {
	head := id
	if dry {
		head += " (dry run)"
	}
	rows := []ui.KV{
		{Key: "Confirmed", Value: countAnd(r.Confirmed), State: ui.StateOK},
	}
	// Both disagreements are shown even when empty is the common case: a farm
	// where the two sides match completely is worth seeing stated, and one
	// where they do not is the reason to run this at all.
	if len(r.LocalOnly) > 0 {
		rows = append(rows, ui.KV{
			Key:   "Local only",
			Value: countAnd(r.LocalOnly) + " — the probe found OpenStack, the control plane did not list it",
			State: ui.StateWarn,
		})
	}
	if len(r.ControlOnly) > 0 {
		rows = append(rows, ui.KV{
			Key:   "Control only",
			Value: countAnd(r.ControlOnly) + " — registered centrally, no probe result",
			State: ui.StateWarn,
		})
	}
	// Reported loudest of the three. A name that fits several hosts is not a
	// gap in the data — it is a question about which machine is meant, and
	// nothing will resolve it until somebody answers.
	if len(r.Held) > 0 {
		rows = append(rows, ui.KV{
			Key:   "Held",
			Value: countAnd(r.Held) + " — the answer was partial, so nothing was demoted",
			State: ui.StateWarn,
		})
	}
	if len(r.Ambiguous) > 0 {
		rows = append(rows, ui.KV{
			Key:   "Ambiguous",
			Value: countAnd(r.Ambiguous) + " — the name fits more than one inventory host; confirmed for none",
			State: ui.StateFail,
		})
	}
	fmt.Fprintf(os.Stdout, "\n%s\n", ui.GroupHeading(head, ""))
	ui.KVs(os.Stdout, rows)
}

// countAnd names a few and counts the rest. A farm with sixty confirmed hosts
// should not print sixty names to say it agreed.
func countAnd(hosts []string) string {
	if len(hosts) == 0 {
		return "none"
	}
	const show = 4
	if len(hosts) <= show {
		return fmt.Sprintf("%d · %s", len(hosts), strings.Join(hosts, ", "))
	}
	return fmt.Sprintf("%d · %s, +%d more", len(hosts), strings.Join(hosts[:show], ", "), len(hosts)-show)
}
