package cli

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// wgForgetCmd removes a host's collected WireGuard rows.
//
// `wg sync` is the only other thing that deletes from these tables, and it does
// so as the first half of replacing one host — which means it can only clean up
// a host it can still reach. A decommissioned gateway is exactly the host it
// cannot, so its interfaces and peers stay in the graph forever, and every
// view built on them keeps drawing a machine that no longer exists.
//
// Gated on `wg-sync` rather than a grant of its own: these are the same rows a
// sync already deletes and rewrites, so the authority to collect a host's
// topology is the authority to drop it.
func wgForgetCmd(env cmdkit.Env) *cobra.Command {
	var opts wgForgetOptions
	cmd := &cobra.Command{
		Use:   "forget [host...]",
		Short: "Remove a host's collected WireGuard rows (decommissioned gateways)",
		Long: `forget deletes the collected interfaces, peers and runtime status for a
host, which nothing else does once the host is unreachable: 'wg sync' clears
those rows only as the first half of replacing them, so a gateway that is gone
can never clear its own.

Declared entities ('wg entity') and endpoint annotations ('wg endpoint') are
left alone — they are operator statements, not collected facts, and each has
its own rm.

  vctl wg forget old-gateway           drop what the sync last saw on it
  vctl wg forget --gone                every collected host the inventory no longer has
  vctl wg forget --gone --dry-run      name them without deleting anything`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWGForget(cmd, env, args, opts)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&opts.gone, "gone", false, "every collected host that is no longer in the inventory")
	f.BoolVar(&opts.dryRun, "dry-run", false, "report what would be removed and change nothing")
	cmd.ValidArgsFunction = completeWGCollectedHost(env)
	return cmdkit.Gate(cmd, "wg-sync")
}

// wgForgetOptions is the bound flag set of `wg forget`.
type wgForgetOptions struct {
	gone   bool
	dryRun bool
}

// runWGForget is the body of `wg forget`, kept apart from the flag wiring.
func runWGForget(cmd *cobra.Command, env cmdkit.Env, args []string, opts wgForgetOptions) error {
	// A dry run opens the store read-only: a preview must not be able to write
	// even if a later edit here got the branch wrong.
	return env.WithStore(cmd.Context(), !opts.dryRun, func(_ *app.App, st *store.Store) error {
		ctx := cmd.Context()
		hosts, err := wgForgetTargets(ctx, st, args, opts.gone)
		if err != nil {
			return err
		}
		if len(hosts) == 0 {
			ui.Infof(os.Stdout, "nothing to forget")
			return nil
		}
		return forgetWGHosts(ctx, st, hosts, opts.dryRun)
	})
}

// wgForgetTargets resolves which hosts to drop, reading both sides from the
// store and handing the decision to wgForgetTargetsFrom.
func wgForgetTargets(ctx context.Context, st *store.Store, args []string, gone bool) ([]string, error) {
	collected, err := st.WGCollectedHosts(ctx)
	if err != nil {
		return nil, err
	}
	var servers []store.Server
	if gone {
		if servers, err = st.List(ctx, ""); err != nil {
			return nil, err
		}
	}
	return wgForgetTargetsFrom(collected, servers, args, gone)
}

// wgForgetTargetsFrom decides the target set, refusing anything the WireGuard
// tables do not actually hold — a typo must not report success. Kept free of
// the store so the guards are testable without a database.
func wgForgetTargetsFrom(collected []string, servers []store.Server, args []string, gone bool) ([]string, error) {
	switch {
	case gone && len(args) > 0:
		return nil, fmt.Errorf("pass host names or --gone, not both")
	case gone:
		return wgHostsNotInInventory(collected, servers), nil
	case len(args) == 0:
		return nil, fmt.Errorf("name the hosts to forget, or pass --gone")
	}
	for _, h := range args {
		if !slices.Contains(collected, h) {
			return nil, fmt.Errorf("%s: no collected WireGuard rows (see 'vctl wg graph')", h)
		}
	}
	return args, nil
}

// wgHostsNotInInventory answers which collected hosts the inventory has since
// lost — the ones no sync can ever clean up again.
func wgHostsNotInInventory(collected []string, servers []store.Server) []string {
	known := make(map[string]bool, len(servers))
	for _, s := range servers {
		known[s.Hostname] = true
	}
	var gone []string
	for _, h := range collected {
		if !known[h] {
			gone = append(gone, h)
		}
	}
	return gone
}

// forgetWGHosts removes each host and reports what went, one line per host so
// an operator can see which of a --gone sweep was the one they cared about.
func forgetWGHosts(ctx context.Context, st *store.Store, hosts []string, dryRun bool) error {
	var total store.WGForgetCounts
	for _, h := range hosts {
		c, err := wgForgetOne(ctx, st, h, dryRun)
		if err != nil {
			return fmt.Errorf("%s: %w", h, err)
		}
		total.Interfaces += c.Interfaces
		total.Peers += c.Peers
		total.Statuses += c.Statuses
		prefix := ""
		if dryRun {
			prefix = "[dry-run] "
		}
		ui.Successf(os.Stdout, "%s%s: %d iface · %d peer · %d status", prefix, h, c.Interfaces, c.Peers, c.Statuses)
	}
	ui.Section(os.Stderr, "wg forget")
	ui.KVs(os.Stderr, []ui.KV{
		{Key: "Hosts", Value: strconv.Itoa(len(hosts))},
		{Key: "Rows removed", Value: strconv.FormatInt(total.Total(), 10), State: ui.StateOK},
	})
	if dryRun {
		ui.Warnf(os.Stderr, "dry run — nothing was deleted")
	}
	return nil
}

// wgForgetOne deletes one host's rows, or counts them on a dry run. Counting
// reads the same three tables the delete walks, so the preview cannot claim a
// different number than the real run would remove.
func wgForgetOne(ctx context.Context, st *store.Store, host string, dryRun bool) (store.WGForgetCounts, error) {
	if !dryRun {
		return st.WGForgetHost(ctx, host)
	}
	return st.WGCountHostRows(ctx, host)
}

// completeWGCollectedHost completes from the hosts the WireGuard tables hold,
// not the inventory: the interesting argument here is usually a host the
// inventory no longer has.
func completeWGCollectedHost(env cmdkit.Env) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var out []string
		_ = env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
			hosts, err := st.WGCollectedHosts(cmd.Context())
			if err != nil {
				return err
			}
			out = hosts
			return nil
		})
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}
