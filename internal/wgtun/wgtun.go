// Package wgtun is a WireGuard tunnel that lives inside the process: a
// wireguard-go device on a userspace TCP/IP stack (gVisor netstack), so vctl
// can reach the fleet's networks without a kernel interface, a TUN device,
// root, or WireGuard installed on the machine. The tunnel is an ordinary
// dialer — `vctl wg connect` puts a SOCKS proxy and port forwards on top of it
// — and it exists only as long as the process does.
//
// Keys and peers come from the caller (vctl reads them from Vault at connect
// time); nothing here touches disk.
package wgtun

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// Peer is the far end: the gateway this side handshakes with and the
// networks reachable through it.
type Peer struct {
	PublicKey    string // base64, as a wg config writes it
	PresharedKey string // base64, optional
	// Endpoint is host:port on the real network. A hostname is resolved once,
	// at Up, with the machine's own resolver — the tunnel is not up yet.
	Endpoint   string
	AllowedIPs []netip.Prefix
	Keepalive  time.Duration
}

// Config is one side of a tunnel.
type Config struct {
	PrivateKey string       // base64
	Addresses  []netip.Addr // this side's tunnel addresses
	// DNS are resolvers reached through the tunnel; DialContext resolves names
	// with them, so a fleet-internal name works without touching the host's
	// resolver.
	DNS        []netip.Addr
	MTU        int // 0 → 1420, the WireGuard default
	ListenPort int // 0 → a random port; a client does not need a fixed one
	Peers      []Peer
	// Verbose turns on wireguard-go's own log to stderr, for a handshake that
	// will not complete.
	Verbose bool
}

// Tunnel is a running device. It is safe to Dial from many goroutines.
type Tunnel struct {
	dev *device.Device
	tun tun.Device
	net *netstack.Net
}

// Up brings a tunnel up. It returns once the device is running; the first
// handshake happens on the first packet, so a wrong key or an unreachable
// endpoint shows up as a Dial that times out, not as an error here — Stats
// tells the two apart.
func Up(cfg Config) (*Tunnel, error) {
	if len(cfg.Addresses) == 0 {
		return nil, errors.New("a tunnel needs at least one address")
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("a tunnel needs at least one peer")
	}
	uapi, err := uapiConfig(cfg)
	if err != nil {
		return nil, err
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	tdev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, mtu)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	level := device.LogLevelSilent
	if cfg.Verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(level, "wg: "))
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring device up: %w", err)
	}
	return &Tunnel{dev: dev, tun: tdev, net: tnet}, nil
}

// DialContext opens a connection through the tunnel. network is "tcp" or
// "udp"; a hostname in address is resolved with the tunnel's DNS.
func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return t.net.DialContext(ctx, network, address)
}

// ListenTCP accepts connections arriving through the tunnel at one of this
// side's addresses. The gateway side of a test uses it; a client rarely does.
func (t *Tunnel) ListenTCP(addr *net.TCPAddr) (net.Listener, error) {
	return t.net.ListenTCP(addr)
}

// Close stops the device and drops every connection through it.
func (t *Tunnel) Close() error {
	t.dev.Close()
	return nil
}

// PeerStat is what the device knows about one peer: whether a handshake has
// ever completed, when, and how much has crossed.
type PeerStat struct {
	PublicKey     string // base64
	Endpoint      string
	LastHandshake time.Time // zero until the first handshake
	RxBytes       uint64
	TxBytes       uint64
}

// Stats reads the device's per-peer counters.
func (t *Tunnel) Stats() ([]PeerStat, error) {
	raw, err := t.dev.IpcGet()
	if err != nil {
		return nil, err
	}
	var out []PeerStat
	var cur *PeerStat
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			out = append(out, PeerStat{PublicKey: hexToBase64(v)})
			cur = &out[len(out)-1]
		case "endpoint":
			if cur != nil {
				cur.Endpoint = v
			}
		case "last_handshake_time_sec":
			if cur != nil {
				if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
					cur.LastHandshake = time.Unix(sec, 0)
				}
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	return out, nil
}

// ListenPort is the UDP port the device is bound to — the one a test's client
// side needs when the gateway side asked for a random port.
func (t *Tunnel) ListenPort() (int, error) {
	raw, err := t.dev.IpcGet()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(raw, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			return strconv.Atoi(v)
		}
	}
	return 0, errors.New("device reports no listen port")
}

// GenerateKey makes a new keypair, base64 as a wg config writes it. The
// private key is clamped the way wg(8) does.
func GenerateKey() (private, public string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// PublicKey derives the public key of a base64 private key.
func PublicKey(private string) (string, error) {
	priv, err := decodeKey(private)
	if err != nil {
		return "", err
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// uapiConfig renders the device's configuration in WireGuard's UAPI form,
// which wants keys in hex and endpoints as literal addresses.
func uapiConfig(cfg Config) (string, error) {
	var b strings.Builder
	priv, err := decodeKey(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(priv))
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	for i, p := range cfg.Peers {
		pub, err := decodeKey(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer %d public key: %w", i+1, err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(pub))
		if p.PresharedKey != "" {
			psk, err := decodeKey(p.PresharedKey)
			if err != nil {
				return "", fmt.Errorf("peer %d preshared key: %w", i+1, err)
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(psk))
		}
		if p.Endpoint != "" {
			addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return "", fmt.Errorf("peer %d endpoint %q: %w", i+1, p.Endpoint, err)
			}
			fmt.Fprintf(&b, "endpoint=%s\n", addr.String())
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(p.Keepalive.Seconds()))
		}
		if len(p.AllowedIPs) == 0 {
			return "", fmt.Errorf("peer %d has no allowed IPs; nothing would be routed to it", i+1)
		}
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip.Masked())
		}
	}
	return b.String(), nil
}

func decodeKey(b64 string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, err
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("key is %d bytes, want 32", len(k))
	}
	return k, nil
}

func hexToBase64(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	return base64.StdEncoding.EncodeToString(b)
}
