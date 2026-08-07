package wireguard

import (
	"strconv"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// Parsing lives beside the collection rather than in the command that happens
// to run it, because dropping the private and preshared keys is part of what
// collection *is*. A second caller that parsed its own output would be one
// keystroke from carrying them into the database.

// ParseCollect turns the combined `wg show all dump` + `ip addr` output into
// store rows for one host. Private/preshared keys are never carried through.
func ParseCollect(host, out string) ([]store.WGInterface, []store.WGPeer, []store.WGPeerStatus) {
	dumpPart, addrPart, _ := strings.Cut(out, "@@ADDR@@")
	pIfaces, pPeers := ParseDump(dumpPart)
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

// ParsedIface is one interface line of the dump.
type ParsedIface struct {
	Name       string
	PublicKey  string
	ListenPort int
	Fwmark     int64
}

// ParsedPeer is one peer line of the dump.
type ParsedPeer struct {
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
func ParseDump(dump string) ([]ParsedIface, []ParsedPeer) {
	var ifaces []ParsedIface
	var peers []ParsedPeer
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		switch {
		case len(f) == 5: // interface (self) line
			ifaces = append(ifaces, ParsedIface{
				Name:       f[0],
				PublicKey:  f[2],
				ListenPort: atoiSafe(f[3]),
				Fwmark:     parseFwmark(f[4]),
			})
		case len(f) >= 8: // peer line
			p := ParsedPeer{
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

// samples converts what the dump parser produced into what the overlay model
// takes.
//
// One small function against the domain package knowing how `wg show all dump`
// formats its columns. The parser's row carries fields the model has no use for
// (keepalive), and the model should not grow them just because they were in the
// output.
