package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstackapi"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// reconcileTimeout bounds one deployment's control-plane conversation. A farm
// whose Keystone is unreachable must not hold up the rest.
const reconcileTimeout = 60 * time.Second

// vaultFarmPrefix is where a deployment's admin credentials live.
//
// Read from Vault at use time and never written anywhere: the whole reason this
// runs centrally rather than on each host is that a status agent should not be
// able to read an OpenStack admin credential. Putting it in a file here would
// give that back.
const vaultFarmPrefix = "kv/teams/sre/openstack"

func openstackReconcileCmd() *cobra.Command {
	var (
		only     string
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
			"Credentials are read from Vault under " + vaultFarmPrefix + "/<deployment>, at use time.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, err := st.LocalOnlyFarms(ctx)
				if err != nil {
					return err
				}
				if len(farms) == 0 {
					ui.Warnf(os.Stderr, "no deployments to reconcile. Run the node agents first.")
					return nil
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
				return reconcileFarms(ctx, a, st, ids, farms, insecure, dryRun)
			})
		},
	}
	cmd.Flags().StringVar(&only, "farm", "", "reconcile only this deployment")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification against the control plane (self-signed endpoints)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change without writing")
	return cmd
}

func reconcileFarms(ctx context.Context, a *app.App, st *store.Store, ids []string,
	farms map[string][]string, insecure, dryRun bool) error {
	ui.Section(os.Stdout, "openstack reconcile")
	var reached int
	for _, id := range ids {
		hosts := farms[id]
		sort.Strings(hosts)

		creds, err := farmCredentials(ctx, a, id)
		if err != nil {
			// A farm with no credentials filed is the normal state until
			// somebody files them, not a failure of the run. The other farms
			// still get reconciled.
			ui.Warnf(os.Stderr, "%s: %v", id, err)
			continue
		}
		control, err := controlPlaneHosts(ctx, creds, insecure)
		if err != nil {
			ui.Errorf(os.Stderr, "%s: %v", id, err)
			continue
		}
		reached++
		if dryRun {
			reportReconcile(id, previewReconcile(hosts, control), true)
			continue
		}
		got, err := st.ReconcileDeployment(ctx, store.ReconcileInput{
			DeploymentID: id, KeystoneURL: id,
			LocalHosts: hosts, ControlHosts: control,
			ObservedAt: time.Now(),
		})
		if err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		reportReconcile(id, got, false)
	}
	if reached == 0 {
		return fmt.Errorf("no deployment could be reached; nothing was confirmed")
	}
	return nil
}

// farmCredentials reads one deployment's admin credentials from Vault.
func farmCredentials(ctx context.Context, a *app.App, id string) (openstackapi.Credentials, error) {
	path := vaultFarmPrefix + "/" + vaultFarmKey(id)
	secret, err := a.Vault.ReadKV(ctx, path)
	if err != nil {
		return openstackapi.Credentials{}, fmt.Errorf("no credentials at %s (%w)", path, err)
	}
	c := openstackapi.Credentials{
		AuthURL:     secret["auth_url"],
		Username:    secret["username"],
		Password:    secret["password"],
		ProjectName: secret["project_name"],
		UserDomain:  secret["user_domain"],
		ProjectDom:  secret["project_domain"],
	}
	if c.AuthURL == "" {
		// The deployment id is the endpoint's host; the scheme is not part of
		// it, so a stored auth_url is what says which one to use.
		return c, fmt.Errorf("credentials at %s carry no auth_url", path)
	}
	return c, nil
}

// vaultFarmKey turns a deployment id into a path segment.
//
// The id is a host:port, and a colon in a Vault path is legal but awkward
// everywhere it is then typed — `vault kv put kv/teams/sre/openstack/10.0.0.1:5000`
// needs quoting, and it reads like a typo. The port matters (two deployments
// can share an address), so it is kept and only the separator changes.
func vaultFarmKey(id string) string {
	return strings.ReplaceAll(id, ":", "_")
}

func controlPlaneHosts(ctx context.Context, c openstackapi.Credentials, insecure bool) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()
	client, err := openstackapi.New(ctx, c, insecure, reconcileTimeout)
	if err != nil {
		return nil, err
	}
	hs, err := client.Hypervisors(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		if h.Hostname != "" {
			out = append(out, h.Hostname)
		}
	}
	return out, nil
}

// previewReconcile computes what a run would decide, without writing. Same
// matching rule as the store, so a dry run is not a different answer.
func previewReconcile(local, control []string) store.ReconcileResult {
	var res store.ReconcileResult
	known := map[string]bool{}
	for _, h := range control {
		known[h] = true
		if short, _, ok := strings.Cut(h, "."); ok {
			known[short] = true
		}
	}
	matched := map[string]bool{}
	for _, h := range local {
		short := h
		if s, _, ok := strings.Cut(h, "."); ok {
			short = s
		}
		if known[h] || known[short] {
			res.Confirmed = append(res.Confirmed, h)
			matched[short] = true
			continue
		}
		res.LocalOnly = append(res.LocalOnly, h)
	}
	for _, h := range control {
		short := h
		if s, _, ok := strings.Cut(h, "."); ok {
			short = s
		}
		if !matched[short] {
			res.ControlOnly = append(res.ControlOnly, h)
		}
	}
	return res
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
