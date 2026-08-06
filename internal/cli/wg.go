package cli

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// wgCollectCmd is the remote command run on each gateway: dump WireGuard state
// (public data only — parsing drops the private/preshared keys) and interface
// addresses. sudo is tried first since `wg show` needs root; a plain fallback
// covers root logins. Both are silenced so a non-WG host yields empty output.
const wgCollectCmd = `{ sudo -n wg show all dump 2>/dev/null || wg show all dump 2>/dev/null; }; echo '@@ADDR@@'; { ip -o -4 addr show 2>/dev/null; ip -o -6 addr show 2>/dev/null; }`

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
			sem := make(chan struct{}, concurrency)
			var mu sync.Mutex
			var wg sync.WaitGroup
			var withWG, ifaceN, peerN, skipped, failed int

			for i := range hosts {
				sv := hosts[i]
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					tgt, err := access.BuildTarget(ctx, st, &sv, a.Cfg.SSHDirectFirst)
					if err != nil {
						mu.Lock()
						failed++
						mu.Unlock()
						ui.Warnf(os.Stderr, "%s: build target: %v", sv.Hostname, err)
						return
					}
					res, err := conn.Execute(ctx, access.Request{Target: tgt, HostKey: access.HostKeyAcceptNew}, wgCollectCmd, timeout)
					if err != nil {
						mu.Lock()
						failed++
						mu.Unlock()
						ui.Warnf(os.Stderr, "%s: %v", sv.Hostname, err)
						return
					}
					ifaces, peers, statuses := parseWGCollect(sv.Hostname, res.Stdout)
					if len(ifaces) == 0 {
						mu.Lock()
						skipped++
						mu.Unlock()
						return
					}
					if !dryRun {
						if err := st.WGReplaceHost(ctx, sv.Hostname, ifaces, peers, statuses); err != nil {
							mu.Lock()
							failed++
							mu.Unlock()
							ui.Warnf(os.Stderr, "%s: store: %v", sv.Hostname, err)
							return
						}
					}
					mu.Lock()
					withWG++
					ifaceN += len(ifaces)
					peerN += len(peers)
					mu.Unlock()
					prefix := ""
					if dryRun {
						prefix = "[dry-run] "
					}
					ui.Successf(os.Stderr, "%s%s: %d iface, %d peer", prefix, sv.Hostname, len(ifaces), len(peers))
				}()
			}
			wg.Wait()

			ui.Section(os.Stderr, "wg sync")
			ui.KVs(os.Stderr, []ui.KV{
				{Key: "Probed", Value: strconv.Itoa(len(hosts))},
				{Key: "With WireGuard", Value: strconv.Itoa(withWG), State: ui.StateOK},
				{Key: "Interfaces", Value: strconv.Itoa(ifaceN)},
				{Key: "Peers", Value: strconv.Itoa(peerN)},
				{Key: "No WireGuard", Value: strconv.Itoa(skipped), State: ui.StateWarn},
				{Key: "Failed", Value: strconv.Itoa(failed), State: ui.StateFail},
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

// parseWGCollect turns the combined `wg show all dump` + `ip addr` output into
// store rows for one host. Private/preshared keys are never carried through.
func parseWGCollect(host, out string) ([]store.WGInterface, []store.WGPeer, []store.WGPeerStatus) {
	dumpPart, addrPart, _ := strings.Cut(out, "@@ADDR@@")
	pIfaces, pPeers := parseWGDump(dumpPart)
	addrs := parseIfaceAddrs(addrPart)

	ifaces := make([]store.WGInterface, 0, len(pIfaces))
	for _, i := range pIfaces {
		ifaces = append(ifaces, store.WGInterface{
			Host: host, Iface: i.Name, ListenPort: i.ListenPort,
			PublicKey: i.PublicKey, Fwmark: i.Fwmark, Address: addrs[i.Name],
		})
	}
	peers := make([]store.WGPeer, 0, len(pPeers))
	statuses := make([]store.WGPeerStatus, 0, len(pPeers))
	for _, p := range pPeers {
		peers = append(peers, store.WGPeer{
			Host: host, Iface: p.Iface, PeerPubKey: p.PubKey, Endpoint: p.Endpoint,
			AllowedIPs: p.AllowedIPs, Keepalive: p.Keepalive,
		})
		var hs *time.Time
		if p.Handshake > 0 {
			t := time.Unix(p.Handshake, 0)
			hs = &t
		}
		statuses = append(statuses, store.WGPeerStatus{
			Host: host, Iface: p.Iface, PeerPubKey: p.PubKey,
			LatestHandshake: hs, RxBytes: p.Rx, TxBytes: p.Tx,
		})
	}
	return ifaces, peers, statuses
}

type wgParsedIface struct {
	Name       string
	PublicKey  string
	ListenPort int
	Fwmark     int64
}

type wgParsedPeer struct {
	Iface      string
	PubKey     string
	Endpoint   string
	AllowedIPs []string
	Handshake  int64
	Rx, Tx     int64
	Keepalive  int
}

// parseWGDump parses `wg show all dump`. Interface lines have 5 tab-separated
// fields (iface, private-key, public-key, listen-port, fwmark); peer lines have
// 8+ (iface, public-key, preshared-key, endpoint, allowed-ips, handshake, rx,
// tx, keepalive). The private and preshared keys are read but discarded.
func parseWGDump(dump string) ([]wgParsedIface, []wgParsedPeer) {
	var ifaces []wgParsedIface
	var peers []wgParsedPeer
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		switch {
		case len(f) == 5: // interface (self) line
			ifaces = append(ifaces, wgParsedIface{
				Name:       f[0],
				PublicKey:  f[2],
				ListenPort: atoiSafe(f[3]),
				Fwmark:     parseFwmark(f[4]),
			})
		case len(f) >= 8: // peer line
			p := wgParsedPeer{
				Iface:      f[0],
				PubKey:     f[1],
				Endpoint:   noneToEmpty(f[3]),
				AllowedIPs: parseAllowedIPs(f[4]),
				Handshake:  atoi64Safe(f[5]),
				Rx:         atoi64Safe(f[6]),
				Tx:         atoi64Safe(f[7]),
			}
			if len(f) >= 9 {
				p.Keepalive = parseKeepalive(f[8])
			}
			peers = append(peers, p)
		}
	}
	return ifaces, peers
}

// parseIfaceAddrs maps interface name -> addresses from `ip -o addr show`.
// Each line looks like: "3: wg0    inet 10.0.90.2/29 scope global wg0 ...".
func parseIfaceAddrs(ipOut string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(ipOut, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		iface := strings.TrimSuffix(f[1], ":")
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "inet" || f[i] == "inet6" {
				out[iface] = append(out[iface], f[i+1])
			}
		}
	}
	return out
}

func parseAllowedIPs(s string) []string {
	if noneToEmpty(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func noneToEmpty(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}

func atoiSafe(s string) int     { n, _ := strconv.Atoi(strings.TrimSpace(s)); return n }
func atoi64Safe(s string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }

func parseKeepalive(s string) int {
	if s == "off" || s == "" {
		return 0
	}
	return atoiSafe(s)
}

// parseFwmark reads the fwmark field ("off" or a 0x hex / decimal value).
func parseFwmark(s string) int64 {
	if s == "off" || s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 0, 64) // base 0 handles 0x-prefixed hex
	if err != nil {
		return 0
	}
	return n
}
