package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

// wgCollectCmd is the remote command run on each gateway: dump WireGuard state
// (public data only — parsing drops the private/preshared keys) and interface
// addresses. sudo is tried first since `wg show` needs root; a plain fallback
// covers root logins. Both are silenced so a non-WG host yields empty output.

func wgCmd(env CommandEnv) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wg",
		Short: "Collect and inspect the WireGuard topology (from vctl-postgres)",
		Long: `wg builds a database-backed picture of the WireGuard mesh: interfaces,
peers (topology edges) and per-peer runtime status, collected by SSHing into the
gateways and running 'wg show'. No secrets are stored — only public keys.`,
	}
	cmd.AddCommand(wgSyncCmd(env), wgGraphCmd(env), wgMonitorCmd(env), wgServeCmd(env), wgEndpointCmd(env))
	return cmd
}

// wgSyncCmd collects WireGuard state from gateways into postgres.
func wgSyncCmd(env CommandEnv) *cobra.Command {
	var (
		dc          string
		all         bool
		dryRun      bool
		timeoutSec  int
		concurrency int
	)
	cmd := &cobra.Command{
		Use:   "sync [host...]",
		Short: "Collect WireGuard state from gateways (SSH + wg show) into the DB",
		Long: `sync SSHes into the given hosts (or all inventory with --all) and records
each host's WireGuard interfaces, peers and runtime status. Hosts without
WireGuard are skipped. --dry-run parses and prints without writing.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.newApp()
			if err != nil {
				return err
			}
			purpose := app.PurposeInventoryWrite
			if dryRun {
				purpose = app.PurposeInventoryRead
			}
			st, err := a.OpenStore(ctx, purpose)
			if err != nil {
				return err
			}
			defer st.Close()

			hosts, err := wgTargetHosts(ctx, st, args, dc, all)
			if err != nil {
				return err
			}
			if len(hosts) == 0 {
				return fmt.Errorf("no target hosts: pass host names, --all, or --dc")
			}

			conn := newConnector(a)
			timeout := time.Duration(timeoutSec) * time.Second
			targets := make([]wireguard.Host, 0, len(hosts))
			for i := range hosts {
				targets = append(targets, wireguard.Host{Name: hosts[i].Hostname, Target: &hosts[i]})
			}
			c := &wireguard.Collector{
				Concurrency: concurrency,
				Run: func(ctx context.Context, h wireguard.Host) (string, error) {
					sv := h.Target.(*store.Server)
					tgt, err := access.BuildTarget(ctx, st, sv, a.Cfg.SSHDirectFirst)
					if err != nil {
						return "", fmt.Errorf("build target: %w", err)
					}
					res, err := conn.Execute(ctx,
						access.Request{Target: tgt, HostKey: access.HostKeyAcceptNew},
						wireguard.CollectCmd, timeout)
					if err != nil {
						return "", err
					}
					return res.Stdout, nil
				},
				OnHost: func(r wireguard.HostResult) {
					switch {
					case r.Err != nil:
						ui.Warnf(os.Stderr, "%s: %v", r.Host, r.Err)
					case r.NoWireGuard:
					default:
						prefix := ""
						if dryRun {
							prefix = "[dry-run] "
						}
						ui.Successf(os.Stderr, "%s%s: %d iface, %d peer", prefix, r.Host, r.Interfaces, r.Peers)
					}
				},
			}
			// A dry run has no sink at all, so what it exercises is the real
			// path minus the write rather than a description of it.
			if !dryRun {
				c.Save = st.WGReplaceHost
			}
			rep := c.Collect(ctx, targets)

			ui.Section(os.Stderr, "wg sync")
			ui.KVs(os.Stderr, []ui.KV{
				{Key: "Probed", Value: strconv.Itoa(rep.Probed)},
				{Key: "With WireGuard", Value: strconv.Itoa(rep.WithWG), State: ui.StateOK},
				{Key: "Interfaces", Value: strconv.Itoa(rep.Interfaces)},
				{Key: "Peers", Value: strconv.Itoa(rep.Peers)},
				{Key: "No WireGuard", Value: strconv.Itoa(rep.Skipped), State: ui.StateWarn},
				{Key: "Failed", Value: strconv.Itoa(rep.Failed), State: ui.StateFail},
			})
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&dc, "dc", "", "restrict to a DC (with no host args)")
	f.BoolVar(&all, "all", false, "probe every inventory host")
	f.BoolVar(&dryRun, "dry-run", false, "parse and report without writing to the DB")
	f.IntVar(&timeoutSec, "timeout", 20, "per-host SSH command timeout (seconds)")
	f.IntVar(&concurrency, "concurrency", 6, "max concurrent gateway probes")
	return gate(cmd, "wg-sync", classMutate)
}

// wgTargetHosts resolves the set of gateways to probe: explicit args, else the
// whole inventory (optionally DC-filtered) when --all or --dc is given.
func wgTargetHosts(ctx context.Context, st *store.Store, args []string, dc string, all bool) ([]store.Server, error) {
	if len(args) > 0 {
		out := make([]store.Server, 0, len(args))
		for _, q := range args {
			sv, err := access.ResolveServer(ctx, st, q)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", q, err)
			}
			out = append(out, *sv)
		}
		return out, nil
	}
	if all || dc != "" {
		return st.List(ctx, dc)
	}
	return nil, nil
}

func samples(peers []wireguard.ParsedPeer) []wireguard.PeerSample {
	out := make([]wireguard.PeerSample, 0, len(peers))
	for _, p := range peers {
		out = append(out, wireguard.PeerSample{
			Iface: p.Iface, PubKey: p.PubKey,
			Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs,
			Rx: p.Rx, Tx: p.Tx, Handshake: p.Handshake,
		})
	}
	return out
}
