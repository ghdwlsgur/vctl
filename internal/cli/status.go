package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func statusCmd(env CommandEnv) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check login and connection status",
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.withApp(func(a *app.App) error {
				ctx := cmd.Context()
				ui.Section(os.Stdout, "vctl status")
				rows := []ui.KV{
					{Key: "Vault", Value: a.Cfg.VaultAddr},
					authMethodRow(ctx, a),
				}
				tokenRow, authenticated := tokenStatus(ctx, a)
				rows = append(rows, tokenRow)
				if !authenticated {
					// Still report the cache: whether host lookup would survive an
					// outage is exactly what someone runs `vctl status` to find out,
					// and it does not depend on being logged in.
					rows = append(rows, cacheStatusRow(a))
					ui.KVs(os.Stdout, rows)
					return nil
				}
				ca, err := a.Vault.SSHCAPublicKey(ctx)
				if err != nil {
					rows = append(rows, ui.KV{Key: "SSH CA", Value: "read failed (" + err.Error() + ")", State: ui.StateFail})
				} else {
					rows = append(rows, ui.KV{Key: "SSH CA", Value: fmt.Sprintf("OK (%.40s...)", ca), State: ui.StateOK})
				}
				st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
				if err != nil {
					rows = append(rows, ui.KV{Key: "Inventory DB", Value: "connection failed (" + err.Error() + ")", State: ui.StateFail})
					rows = append(rows, cacheStatusRow(a))
					ui.KVs(os.Stdout, rows)
					return nil
				}
				defer st.Close()
				servers, err := st.ListWithStatus(ctx, "")
				if err != nil {
					rows = append(rows, ui.KV{Key: "Inventory DB", Value: "query failed (" + err.Error() + ")", State: ui.StateFail})
					rows = append(rows, cacheStatusRow(a))
					ui.KVs(os.Stdout, rows)
					return nil
				}
				rows = append(rows, ui.KV{Key: "Inventory DB", Value: fmt.Sprintf("OK · %d hosts", len(servers)), State: ui.StateOK})
				agents := summarizeAgents(servers, time.Now())
				agentState := agents.State()
				managed := agents.Reporting + agents.Stale
				rows = append(rows, ui.KV{
					Key:   "Node agents",
					State: agentState,
					Raw:   fmt.Sprintf("%s  %s", ui.Badge(agentState, agents.Text()), ui.Bar(agents.Reporting, managed, 12)),
				})
				rows = append(rows, cacheStatusRow(a))
				ui.KVs(os.Stdout, rows)
				return nil
			})
		},
	}
}

type agentSummary struct {
	Reporting int
	Stale     int
	Unmanaged int
}

// summarizeAgents keeps the management denominator honest. A server_status row
// proves an agent was installed at least once; its freshness says whether that
// managed agent is healthy now. Inventory with no row is unmanaged, not a
// failed installation, and therefore does not dilute the reporting ratio.
func summarizeAgents(servers []store.ServerWithStatus, now time.Time) agentSummary {
	var summary agentSummary
	for _, server := range servers {
		switch {
		case server.Status == nil:
			summary.Unmanaged++
		case !server.Status.LastSeenAt.Before(now.Add(-statusFreshnessWindow)):
			summary.Reporting++
		default:
			summary.Stale++
		}
	}
	return summary
}

func (s agentSummary) Text() string {
	return fmt.Sprintf("%d reporting · %d stale · %d unmanaged", s.Reporting, s.Stale, s.Unmanaged)
}

func (s agentSummary) State() ui.State {
	if s.Reporting == 0 || s.Stale > 0 {
		return ui.StateWarn
	}
	return ui.StateOK
}

// authMethodRow says which identity vctl actually holds.
//
// This row used to print the configured method alone, which is the one thing
// that cannot be wrong. A workstation configured for userpass ran on an AppRole
// token for hours — reads worked, so nothing looked amiss, while ssh, edit and
// reconcile returned 403 — and this line said "userpass" throughout.
//
// The signal is not "the method differs from the config". A person logging in
// gets oidc here even where the config says userpass, and that is a working
// session rather than a fault. What separates the two is the entity behind the
// token: a human login carries identity policies from group membership, a
// machine login carries none. Both cases measured on this workstation had the
// *same* token policy — the AppRole's was `default, vctl-user` with no identity
// policies, the person's was the same plus five from their groups.
//
// It reports what the identity is and does not predict which commands will
// fail. A first version did, and printed "ssh will not work" directly above a
// line reporting that the SSH CA read had succeeded.
func authMethodRow(ctx context.Context, a *app.App) ui.KV {
	// One lookup answers both questions this row asks (who, via which
	// method). Diagnostic: a failed lookup renders as "not logged in" rather
	// than failing the status screen that exists to show broken states.
	info, err := a.Vault.LookupToken(ctx)
	if err != nil || info.Identity == "" {
		want := a.Cfg.AuthMethod
		if want == "" {
			want = "userpass"
		}
		return ui.KV{Key: "Auth method", Value: want}
	}
	// Unattended callers name their own method, so this only fires where
	// somebody meant to be themselves and is not.
	if !machineIdentity(info.AuthMethod) || machineIdentity(a.Cfg.AuthMethod) {
		return ui.KV{Key: "Auth method", Value: info.Identity}
	}
	return ui.KV{
		Key: "Auth method",
		Value: fmt.Sprintf("%s — a machine identity, not yours. "+
			"Run 'vctl login' to hold your own group policies", info.Identity),
		State: ui.StateWarn,
	}
}

// machineIdentity reports whether a method authenticates a workload rather than
// a person. Those tokens carry no group membership, and that absence is what
// the narrow policy set comes down to.
func machineIdentity(method string) bool {
	switch strings.ToLower(method) {
	case "approle", "kubernetes":
		return true
	default:
		return false
	}
}

// tokenStatus reports the authentication state and whether the checks below it
// can run at all.
//
// A cached token is not the only way to be authenticated: with AppRole
// credentials on disk vctl authenticates silently, which is how the host agents
// and any non-interactive caller work. Reporting those as "missing; run 'vctl
// login'" and stopping was wrong twice over — the advice is unnecessary, and it
// hid the SSH CA and inventory checks from exactly the setups that most need a
// status command.
func tokenStatus(ctx context.Context, a *app.App) (ui.KV, bool) {
	if a.Vault.HasValidToken() {
		return ui.KV{Key: "Token", Value: fmt.Sprintf("valid · %s left", ui.CompactDuration(a.Vault.TTL())), State: ui.StateOK}, true
	}
	if _, _, haveAppRole := a.AppRoleCreds(); haveAppRole {
		if err := a.ReAuthNonInteractive(ctx); err != nil {
			return ui.KV{Key: "Token", Value: "AppRole authentication failed (" + err.Error() + ")", State: ui.StateFail}, false
		}
		return ui.KV{Key: "Token", Value: fmt.Sprintf("valid · %s left (AppRole)", ui.CompactDuration(a.Vault.TTL())), State: ui.StateOK}, true
	}
	// Only now is a login genuinely required. status never prompts for one —
	// it reports.
	return ui.KV{Key: "Token", Value: "missing; run 'vctl login'", State: ui.StateWarn}, false
}

// cacheStatusRow summarizes whether host lookup would survive a database
// outage. `vctl cache status` has the detail; this is the one line that belongs
// in the overall health check.
func cacheStatusRow(a *app.App) ui.KV {
	if a.Cfg.CacheDisabled {
		return ui.KV{Key: "Local cache", Value: "disabled", State: ui.StateWarn}
	}
	snap, err := a.CacheFile().Load()
	if err != nil || !snap.HasInventory() {
		// status deliberately has no side effects, so it never fills the cache
		// itself — it says what would.
		return ui.KV{Key: "Local cache", Value: "empty — run 'vctl cache refresh', or Postgres going down takes host lookup with it", State: ui.StateWarn}
	}
	now := time.Now()
	age := ui.CompactDuration(snap.Age(now))
	if snap.Expired(now, a.Cfg.CacheStaleLimit()) {
		return ui.KV{Key: "Local cache", Value: fmt.Sprintf("%d hosts · %s old — too stale to serve", len(snap.Servers), age), State: ui.StateFail}
	}
	return ui.KV{Key: "Local cache", Value: fmt.Sprintf("%d hosts · %s old", len(snap.Servers), age), State: ui.StateOK}
}
