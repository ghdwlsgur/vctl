package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/socks5"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
	"github.com/ghdwlsgur/vctl/internal/wgtun"
)

// wgConnectCmd wires the flags for `vctl wg connect`; the work is runWGConnect.
func wgConnectCmd(env cmdkit.Env) *cobra.Command {
	var opts wgConnectOptions
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Reach the fleet's networks through a WireGuard tunnel inside vctl — no WireGuard install, no root",
		Long: `connect brings up a WireGuard tunnel inside this process and puts a SOCKS5
proxy in front of it. Nothing is installed and nothing needs root: the tunnel
is a userspace device that exists only while this command runs.

The peer — your private key, tunnel address and the gateway — is read from
Vault at connect time and never written to disk. The first time, generate a
key and hand its public half to a gateway administrator:

  vctl wg connect --init          # stores a new key in Vault, prints the public key
  vctl wg connect                 # once the administrator has registered the peer

Then point clients at the proxy. Names are resolved through the tunnel, so
fleet-internal hostnames work:

  export HTTPS_PROXY=socks5h://127.0.0.1:1080      # kubectl, curl, helm, …
  kubectl --context <cluster> get nodes
  ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' user@host

  # or, per cluster in kubeconfig:  clusters[].cluster.proxy-url: socks5://127.0.0.1:1080

--forward adds fixed local ports for clients that cannot use a proxy, in ssh -L
form: --forward 6443:10.20.0.5:6443. Ctrl-C disconnects.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runWGConnect(cmd, env, opts)
		},
	}
	cmd.Flags().StringVar(&opts.socks, "socks", "127.0.0.1:1080", "SOCKS5 proxy address; empty disables it")
	cmd.Flags().StringArrayVar(&opts.forwards, "forward", nil, "fixed TCP forward LPORT:HOST:PORT through the tunnel (repeatable)")
	cmd.Flags().StringVar(&opts.peerPath, "peer", "", "Vault KV path of the peer secret (default: config wg_peer_kv_path)")
	cmd.Flags().DurationVar(&opts.keepalive, "keepalive", 25*time.Second, "persistent keepalive toward the gateway")
	cmd.Flags().DurationVar(&opts.status, "status-every", 10*time.Second, "how often to print handshake age and traffic; 0 silences it")
	cmd.Flags().BoolVar(&opts.initKey, "init", false, "generate a key, store it in Vault, print the public key, and exit")
	cmd.Flags().BoolVar(&opts.debug, "debug", false, "print wireguard-go's own log")
	return cmdkit.Gate(cmd, "wg-connect")
}

// wgConnectOptions is the bound flag set of `wg connect`.
type wgConnectOptions struct {
	socks     string
	forwards  []string
	peerPath  string
	keepalive time.Duration
	status    time.Duration
	initKey   bool
	debug     bool
}

// wgPeer is the peer secret as vctl reads it: the fields the tunnel needs
// plus a name for the screen and the audit row.
type wgPeer struct {
	Name string // peer_name — the gateway's inventory name, when the admin set it
	cfg  wgtun.Config
}

// wgPeerFields documents the secret's shape once, for the error that names a
// missing field and for the --init template an administrator completes.
var wgPeerFields = []struct{ key, meaning string }{
	{"private_key", "this side's private key (written by --init)"},
	{"address", "this side's tunnel address, e.g. 10.20.0.9/32"},
	{"peer_public_key", "the gateway's public key"},
	{"peer_endpoint", "the gateway's host:port on the real network"},
	{"allowed_ips", "networks reachable through the gateway, comma-separated CIDRs"},
	{"dns", "optional: resolvers reached through the tunnel, comma-separated"},
	{"preshared_key", "optional"},
	{"mtu", "optional, default 1420"},
	{"peer_name", "optional: the gateway's inventory name, for the screen and the audit row"},
}

func runWGConnect(cmd *cobra.Command, env cmdkit.Env, opts wgConnectOptions) error {
	forwards, err := parseForwards(opts.forwards)
	if err != nil {
		return err
	}
	return env.WithApp(func(a *app.App) error {
		ctx := cmd.Context()
		if err := a.EnsureLogin(ctx); err != nil {
			return err
		}
		info, err := a.Vault.LookupToken(ctx)
		if err != nil {
			return err
		}
		path := wgPeerPath(a.Cfg.WGPeerKVPath, opts.peerPath, info)
		if opts.initKey {
			return wgConnectInit(ctx, a.Vault, path)
		}
		peer, err := loadWGPeer(ctx, a.Vault, path, opts.keepalive, opts.debug)
		if err != nil {
			return err
		}
		return connectAndServe(ctx, a, info, peer, opts, forwards)
	})
}

// wgPeerPath is the secret path: the flag, else the configured template with
// its placeholders filled from the token.
func wgPeerPath(template, flag string, info vaultc.TokenInfo) string {
	if flag != "" {
		return flag
	}
	p := strings.ReplaceAll(template, "{entity}", info.EntityID)
	return strings.ReplaceAll(p, "{identity}", info.Identity)
}

// wgConnectInit makes this person's key and leaves it in Vault, printing only
// the public half. It refuses to overwrite: a key already there is registered
// on a gateway, and replacing it silently would lock that person out.
func wgConnectInit(ctx context.Context, v *vaultc.Client, path string) error {
	if have, err := v.ReadKV(ctx, path); err == nil && have["private_key"] != "" {
		return fmt.Errorf("%s already holds a key (public %s); delete the secret first if you really want a new one", path, have["public_key"])
	}
	priv, pub, err := wgtun.GenerateKey()
	if err != nil {
		return err
	}
	if err := v.WriteKV(ctx, path, map[string]string{"private_key": priv, "public_key": pub}); err != nil {
		return err
	}
	ui.Successf(os.Stderr, "key stored at %s — the private half stays in Vault and is never printed.", path)
	fmt.Fprintf(os.Stdout, "public key: %s\n", pub)
	fmt.Fprintln(os.Stderr)
	ui.Infof(os.Stderr, "next, a gateway administrator registers this public key as a peer and completes the secret:")
	fmt.Fprintf(os.Stderr, "\n  vault kv patch %s \\\n", path)
	for _, f := range wgPeerFields {
		if f.key == "private_key" {
			continue
		}
		fmt.Fprintf(os.Stderr, "    %s=<%s> \\\n", f.key, f.meaning)
	}
	fmt.Fprintln(os.Stderr, "\n  then: vctl wg connect")
	return nil
}

// loadWGPeer reads the secret and turns it into a tunnel configuration.
// Errors name the field, never its value: this is credential material.
func loadWGPeer(ctx context.Context, v *vaultc.Client, path string, keepalive time.Duration, debug bool) (*wgPeer, error) {
	sec, err := v.ReadKV(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("no WireGuard peer at %s (%w) — run `vctl wg connect --init` first", path, err)
	}
	return parseWGPeer(sec, path, keepalive, debug)
}

func parseWGPeer(sec map[string]string, path string, keepalive time.Duration, debug bool) (*wgPeer, error) {
	for _, k := range []string{"private_key", "address", "peer_public_key", "peer_endpoint", "allowed_ips"} {
		if strings.TrimSpace(sec[k]) == "" {
			if k == "private_key" {
				return nil, fmt.Errorf("%s has no private_key — run `vctl wg connect --init`", path)
			}
			return nil, fmt.Errorf("%s has no %s — the peer is not registered yet (an administrator completes the secret)", path, k)
		}
	}
	addr, err := parseTunnelAddress(sec["address"])
	if err != nil {
		return nil, fmt.Errorf("%s: address: %w", path, err)
	}
	allowed, err := parseCIDRList(sec["allowed_ips"])
	if err != nil {
		return nil, fmt.Errorf("%s: allowed_ips: %w", path, err)
	}
	var dns []netip.Addr
	for _, s := range splitList(sec["dns"]) {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%s: dns: %q is not an address", path, s)
		}
		dns = append(dns, ip)
	}
	mtu := 0
	if s := strings.TrimSpace(sec["mtu"]); s != "" {
		if mtu, err = strconv.Atoi(s); err != nil || mtu < 576 {
			return nil, fmt.Errorf("%s: mtu must be a number of at least 576", path)
		}
	}
	return &wgPeer{
		Name: strings.TrimSpace(sec["peer_name"]),
		cfg: wgtun.Config{
			PrivateKey: sec["private_key"],
			Addresses:  []netip.Addr{addr},
			DNS:        dns,
			MTU:        mtu,
			Verbose:    debug,
			Peers: []wgtun.Peer{{
				PublicKey:    strings.TrimSpace(sec["peer_public_key"]),
				PresharedKey: strings.TrimSpace(sec["preshared_key"]),
				Endpoint:     strings.TrimSpace(sec["peer_endpoint"]),
				AllowedIPs:   allowed,
				Keepalive:    keepalive,
			}},
		},
	}, nil
}

// parseTunnelAddress accepts "10.20.0.9/32" or "10.20.0.9".
func parseTunnelAddress(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr(), nil
	}
	return netip.ParseAddr(s)
}

func parseCIDRList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range splitList(s) {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			// A bare address is that host.
			ip, err2 := netip.ParseAddr(item)
			if err2 != nil {
				return nil, fmt.Errorf("%q is not a CIDR", item)
			}
			p = netip.PrefixFrom(ip, ip.BitLen())
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, errors.New("empty")
	}
	return out, nil
}

// splitList splits on commas and whitespace, dropping empties.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

// wgForward is one --forward: a loopback port that dials a fixed far address.
type wgForward struct {
	local  string // 127.0.0.1:LPORT
	target string // HOST:PORT through the tunnel
}

// parseForwards reads LPORT:HOST:PORT, the shape ssh -L uses.
func parseForwards(specs []string) ([]wgForward, error) {
	var out []wgForward
	for _, s := range specs {
		lport, rest, ok := strings.Cut(s, ":")
		if !ok {
			return nil, fmt.Errorf("--forward %q: want LPORT:HOST:PORT", s)
		}
		if n, err := strconv.Atoi(lport); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--forward %q: %q is not a port", s, lport)
		}
		if _, _, err := net.SplitHostPort(rest); err != nil {
			return nil, fmt.Errorf("--forward %q: %q is not HOST:PORT", s, rest)
		}
		out = append(out, wgForward{local: net.JoinHostPort("127.0.0.1", lport), target: rest})
	}
	return out, nil
}

// connectAndServe brings the tunnel up, opens the listeners, records the
// access, and stays until the signal or the context ends it.
func connectAndServe(ctx context.Context, a *app.App, info vaultc.TokenInfo, peer *wgPeer, opts wgConnectOptions, forwards []wgForward) error {
	ctx, stop := signal.NotifyContext(ctx, shutdownSignals()...)
	defer stop()

	tun, err := wgtun.Up(peer.cfg)
	if err != nil {
		logWGAccess(ctx, a, info, peer, false, err)
		return err
	}
	defer tun.Close()

	// Listeners first, so a port in use fails before anything is announced.
	var socksLn net.Listener
	if opts.socks != "" {
		if socksLn, err = net.Listen("tcp", opts.socks); err != nil {
			return fmt.Errorf("SOCKS listener: %w", err)
		}
		defer socksLn.Close()
	}
	fwdLns := make([]net.Listener, 0, len(forwards))
	for _, f := range forwards {
		ln, err := net.Listen("tcp", f.local)
		if err != nil {
			return fmt.Errorf("forward %s: %w", f.local, err)
		}
		defer ln.Close()
		fwdLns = append(fwdLns, ln)
	}
	logWGAccess(ctx, a, info, peer, true, nil)

	gw := peer.Name
	if gw == "" {
		gw = peer.cfg.Peers[0].Endpoint
	}
	ui.Successf(os.Stderr, "tunnel up: %s via %s (%s)", peer.cfg.Addresses[0], gw, peer.cfg.Peers[0].Endpoint)
	if socksLn != nil {
		ui.Infof(os.Stderr, "SOCKS5 proxy on %s", socksLn.Addr())
		fmt.Fprintf(os.Stderr, "     export HTTPS_PROXY=socks5h://%s      # kubectl, curl, helm\n", socksLn.Addr())
		fmt.Fprintf(os.Stderr, "     ssh -o ProxyCommand='nc -x %s %%h %%p' user@host\n", socksLn.Addr())
		go func() { _ = socks5.Serve(ctx, socksLn, tun.DialContext) }()
	}
	for i, f := range forwards {
		ui.Infof(os.Stderr, "forward %s → %s", fwdLns[i].Addr(), f.target)
		go func(ln net.Listener, target string) { _ = socks5.Forward(ctx, ln, target, tun.DialContext) }(fwdLns[i], f.target)
	}
	if len(peer.cfg.DNS) == 0 {
		ui.Warnf(os.Stderr, "the peer secret sets no dns — names will not resolve through the tunnel; use addresses, or add dns=<resolver>")
	}
	ui.Infof(os.Stderr, "Ctrl-C to disconnect")

	return watchTunnel(ctx, tun, opts.status)
}

// watchTunnel prints handshake age and traffic until ctx ends, and says so
// once if no handshake arrives — the one failure a userspace tunnel has no
// other way to report, since a wrong key looks exactly like silence.
func watchTunnel(ctx context.Context, tun *wgtun.Tunnel, every time.Duration) error {
	if every <= 0 {
		<-ctx.Done()
		return nil
	}
	started := time.Now()
	warned := false
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr)
			ui.Infof(os.Stderr, "disconnected.")
			return nil
		case now := <-t.C:
			stats, err := tun.Stats()
			if err != nil || len(stats) == 0 {
				continue
			}
			s := stats[0]
			if s.LastHandshake.IsZero() {
				if !warned && now.Sub(started) > 15*time.Second {
					warned = true
					ui.Warnf(os.Stderr, "no handshake yet after %s — is this public key registered on the gateway, and is %s reachable from here?",
						now.Sub(started).Round(time.Second), s.Endpoint)
				}
				continue
			}
			ui.Infof(os.Stderr, "handshake %s ago · rx %s · tx %s",
				now.Sub(s.LastHandshake).Round(time.Second), humanBytes(int64(s.RxBytes)), humanBytes(int64(s.TxBytes)))
		}
	}
}

// logWGAccess records the connection like an SSH access: who, to which
// gateway, from where, and whether it came up. Best effort — a failed write
// spools, as every access row does.
func logWGAccess(ctx context.Context, a *app.App, info vaultc.TokenInfo, peer *wgPeer, ok bool, cause error) {
	host := peer.Name
	if host == "" {
		host = peer.cfg.Peers[0].Endpoint
	}
	e := store.AccessEntry{
		VaultUser:  info.Identity,
		Hostname:   host,
		ClientUser: "wg-connect",
		TargetAddr: peer.cfg.Addresses[0].String(),
		SignedAt:   time.Now(),
		OK:         ok,
	}
	if cause != nil {
		e.Error = cause.Error()
	}
	if err := a.LogAccess(ctx, e); err != nil {
		ui.Warnf(os.Stderr, "access log: %v", err)
	}
}
