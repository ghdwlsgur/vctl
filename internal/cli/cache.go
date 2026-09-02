package cli

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/invcache"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// cacheCmd exposes the local inventory snapshot that keeps `vctl ssh` and
// `vctl list` working while Postgres is unreachable.
//
// The subcommands are inspection and manual control only; the snapshot refreshes
// itself during ordinary online use, so `refresh` exists for the case where
// someone knows they are about to lose connectivity.
func cacheCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect the local inventory snapshot used when Postgres is unreachable",
		Long: `The local snapshot is a read-only copy of the host inventory kept under
~/.vctl/cache. It is refreshed during normal online use and is read only when
the inventory database cannot be reached. Writes always go to Postgres.

  vctl cache status     show snapshot age, host count, and queued audit records
  vctl cache refresh    refresh the snapshot now (before going offline)
  vctl cache clear      delete the snapshot and cached grants`,
	}
	cmd.AddCommand(cacheStatusCmd(env), cacheRefreshCmd(env), cacheClearCmd(env))
	return cmd
}

func cacheStatusCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show local snapshot age and queued audit records",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.WithApp(func(a *app.App) error {
				ui.Section(os.Stdout, "Local inventory cache")
				if a.Cfg.CacheDisabled {
					ui.Warnf(os.Stdout, "disabled (VCTL_CACHE_DISABLE / cache_disabled)")
					return nil
				}
				f := a.CacheFile()
				fmt.Fprintf(os.Stdout, "  path            %s\n", f.Path)

				snap, err := f.Load()
				switch {
				case err != nil:
					ui.Warnf(os.Stdout, "no snapshot yet — run 'vctl cache refresh' while the database is reachable")
				case !snap.HasInventory():
					// Grants can be cached before any inventory has been. Saying
					// "0 hosts, captured just now" would imply a usable snapshot.
					ui.Warnf(os.Stdout, "no hosts captured yet — run 'vctl cache refresh' while the database is reachable")
					renderCachedGrants(a, snap)
				default:
					now := time.Now()
					age := snap.Age(now)
					state := ""
					if snap.Expired(now, a.Cfg.CacheStaleLimit()) {
						state = "  " + ui.Fail("expired — will not be served")
					}
					fmt.Fprintf(os.Stdout, "  captured        %s ago (%s)%s\n",
						strutil.CompactDuration(age), snap.CapturedAt.Local().Format(time.RFC3339), state)
					fmt.Fprintf(os.Stdout, "  hosts           %d\n", len(snap.Servers))
					fmt.Fprintf(os.Stdout, "  refresh after   %s\n", a.Cfg.CacheRefreshInterval())
					if limit := a.Cfg.CacheStaleLimit(); limit > 0 {
						fmt.Fprintf(os.Stdout, "  serve until     %s old\n", limit)
					}
					renderCachedGrants(a, snap)
				}

				if pending, err := a.Spool().Pending(); err == nil && pending > 0 {
					ui.Warnf(os.Stdout, "%d access record(s) queued — they flush on the next successful audit write", pending)
				}
				return nil
			})
		},
	}
}

// renderCachedGrants reports the offline authorization window per identity, so
// an operator can tell before an outage whether `vctl ssh` will still be
// permitted during one.
//
// The valid/expired verdict comes from authz rather than a comparison written
// here. Re-deriving it is how the two drifted apart once already, and a status
// command that disagrees with the gate it is reporting on is worse than no
// status command.
func renderCachedGrants(a *app.App, snap *invcache.Snapshot) {
	if len(snap.Grants) == 0 {
		return
	}
	window := a.Cfg.CacheOfflineWindow()
	now := time.Now()
	fmt.Fprintf(os.Stdout, "  offline window  %s\n", window)

	identities := make([]string, 0, len(snap.Grants))
	for identity := range snap.Grants {
		identities = append(identities, identity)
	}
	sort.Strings(identities) // map order would reshuffle the report between runs

	for _, identity := range identities {
		g := cmdkit.CachedGrant(snap.Grants[identity])
		state := ui.OK("valid")
		if g.Expired(now, window) {
			state = ui.Fail("expired")
		}
		fmt.Fprintf(os.Stdout, "  grants          %s  %v  (confirmed %s ago, %s)\n",
			identity, g.Commands, strutil.CompactDuration(g.Age(now)), state)
	}
}

func cacheRefreshCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Refresh the local snapshot from Postgres now",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return env.WithPurposeStore(ctx, app.PurposeInventoryRead, func(a *app.App, st *store.Store) error {
				snap, err := a.CaptureSnapshot(ctx, st)
				if err != nil {
					return err
				}
				ui.Successf(os.Stderr, "cached %d hosts to %s", len(snap.Servers), a.CacheFile().Path)
				return nil
			})
		},
	}
}

func cacheClearCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Delete the local snapshot and cached grants",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.WithApp(func(a *app.App) error {
				f := a.CacheFile()
				if err := f.Clear(); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "removed %s", f.Path)
				// The spool is deliberately left alone: it holds access records
				// that have not reached the audit log yet, and clearing a cache
				// must not destroy audit data.
				if pending, err := a.Spool().Pending(); err == nil && pending > 0 {
					ui.Infof(os.Stderr, "%d queued access record(s) kept — they are audit data, not cache", pending)
				}
				return nil
			})
		},
	}
}
