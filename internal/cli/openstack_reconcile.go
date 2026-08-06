package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
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

// vaultFarmPrefix is where a deployment's admin credentials live.
//
// Read from Vault at use time and never written anywhere: the whole reason this
// runs centrally rather than on each host is that a status agent should not be
// able to read an OpenStack admin credential. Putting it in a file here would
// give that back.
const vaultFarmPrefix = "kv/teams/sre"

func openstackReconcileCmd(env CommandEnv) *cobra.Command {
	var (
		only     string
		self     bool
		hostname string
		insecure bool
		dryRun   bool
	)
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Ask each deployment's control plane which hosts it owns, and confirm membership",
		Long: "The probe can only say a host points at a Keystone. Two deployments behind one proxy\n" +
			"look identical from a host, so that inference is recorded as local-only.\n\n" +
			"This asks nova which compute hosts each deployment actually owns and promotes the\n" +
			"hosts both sides agree on to confirmed. Disagreements are reported, not resolved.\n\n" +
			"Credentials are read from Vault under " + vaultFarmPrefix + "/vctl-<host_port>, at use time.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.withStore(cmd.Context(), true, func(a *app.App, st *store.Store) error {
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
					id, err := resolveFarmID(ctx, st, only)
					if err != nil {
						return err
					}
					only = id
				}
				ids := make([]string, 0, len(farms))
				for id := range farms {
					if only != "" && !strings.EqualFold(id, only) {
						continue
					}
					ids = append(ids, id)
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
					Creds: vaultCredentials{app: a},
					Cloud: novaCloud{},
					Repo:  storeRepo{st: st},
				}
				ui.Section(os.Stdout, "openstack reconcile")
				rep, err := svc.Run(ctx, req)
				// Rendered before the error is returned: a run that reached
				// nothing still has per-farm reasons worth reading.
				renderReconcile(rep, dryRun)
				return err
			})
		},
	}
	cmd.Flags().StringVar(&only, "farm", "", "reconcile only this deployment")
	cmd.Flags().BoolVar(&self, "self", false, "reconcile only the deployment this host belongs to")
	cmd.Flags().StringVar(&hostname, "hostname", "", "inventory hostname for --self; defaults to the os hostname")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification against the control plane (self-signed endpoints)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change without writing")
	return cmd
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

// vaultFarmKey turns a deployment id into a path segment.
//
// The vctl- prefix is what keeps these apart from everything else the team
// stores under kv/teams/sre, which is a shared space.
//
// The id is a host:port, and a colon in a Vault path is legal but awkward
// everywhere it is then typed — it needs quoting, and it reads like a typo. The
// port matters (two deployments can share an address), so it is kept and only
// the separator changes.
func vaultFarmKey(id string) string {
	return "vctl-" + strings.ReplaceAll(id, ":", "_")
}

func reportReconcile(id string, r store.ReconcileResult, dry bool) {
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
	fmt.Fprintf(os.Stdout, "\n%s\n", ui.Title("▌ "+head))
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
