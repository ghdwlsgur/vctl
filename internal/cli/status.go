package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
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
				servers, _ := st.ListWithStatus(ctx, "")
				// "Reporting" has to mean reporting now, not ever. Counting any
				// host with a server_status row read as healthy while every agent
				// in production had been silent for two days — the row survives the
				// agent. `vctl list` already judges the same data by freshness, so
				// this brings the two into agreement.
				var withAgent int
				for _, server := range servers {
					if liveStatusText(server) == "up" {
						withAgent++
					}
				}
				rows = append(rows, ui.KV{Key: "Inventory DB", Value: fmt.Sprintf("OK · %d hosts", len(servers)), State: ui.StateOK})
				agentState := agentCoverageState(len(servers), withAgent)
				rows = append(rows, ui.KV{
					Key:   "Node agents",
					State: agentState,
					Raw:   fmt.Sprintf("%s  %s", ui.Badge(agentState, fmt.Sprintf("%d/%d reporting", withAgent, len(servers))), ui.Bar(withAgent, len(servers), 12)),
				})
				rows = append(rows, cacheStatusRow(a))
				ui.KVs(os.Stdout, rows)
				return nil
			})
		},
	}
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
	who := a.Vault.Identity(ctx)
	if who == "" {
		want := a.Cfg.AuthMethod
		if want == "" {
			want = "userpass"
		}
		return ui.KV{Key: "Auth method", Value: want}
	}
	// Unattended callers name their own method, so this only fires where
	// somebody meant to be themselves and is not.
	if !machineIdentity(a.Vault.TokenAuthMethod(ctx)) || machineIdentity(a.Cfg.AuthMethod) {
		return ui.KV{Key: "Auth method", Value: who}
	}
	return ui.KV{
		Key: "Auth method",
		Value: fmt.Sprintf("%s — a machine identity, not yours. "+
			"Run 'vctl login' to hold your own group policies", who),
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

func agentCoverageState(total, reporting int) ui.State {
	if total == 0 || reporting == 0 {
		return ui.StateWarn
	}
	if reporting == total {
		return ui.StateOK
	}
	return ui.StateWarn
}
