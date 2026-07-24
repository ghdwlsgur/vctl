package cli

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// sampleDump mimics `wg show all dump` (tab-separated) plus the @@ADDR@@ marker
// and `ip -o addr show` lines the collector command emits.
func sampleCollect() string {
	priv := "PRIVATEKEYPRIVATEKEYPRIVATEKEYPRIVATEKEY0000="
	psk := "PRESHAREDKEYPRESHAREDKEYPRESHAREDKEYPRE0000="
	lines := []string{
		// interface (self): iface, private-key, public-key, listen-port, fwmark
		strings.Join([]string{"wg0", priv, "FfQTWz5kWetrGdNbuftAdp51PfXXZQdk4mwuLJ/0vkM=", "51820", "off"}, "\t"),
		// peer: iface, public-key, psk, endpoint, allowed-ips, handshake, rx, tx, keepalive
		strings.Join([]string{"wg0", "Vdoh9AO900DUugmf/QskCHAp0b2meK6aAvWtVSiPD0A=", psk, "192.168.10.1:16925", "10.0.90.1/32,192.168.201.0/24", "1690000000", "123456", "654321", "25"}, "\t"),
		strings.Join([]string{"wg0", "xF9EHt2fUr7xmpgSKB+kJA3jjDtGJFkVw0xy/so4MB0=", "(none)", "(none)", "10.0.90.3/32", "0", "0", "0", "off"}, "\t"),
		"@@ADDR@@",
		"5: wg0    inet 10.0.90.2/29 scope global wg0\\       valid_lft forever preferred_lft forever",
	}
	return strings.Join(lines, "\n")
}

func TestParseWGCollect(t *testing.T) {
	ifaces, peers, statuses := parseWGCollect("wg-gw-incheon", sampleCollect())

	if len(ifaces) != 1 {
		t.Fatalf("ifaces = %d, want 1", len(ifaces))
	}
	i := ifaces[0]
	if i.Iface != "wg0" || i.ListenPort != 51820 || i.Fwmark != 0 {
		t.Errorf("iface parse wrong: %+v", i)
	}
	if i.PublicKey != "FfQTWz5kWetrGdNbuftAdp51PfXXZQdk4mwuLJ/0vkM=" {
		t.Errorf("iface pubkey wrong: %q", i.PublicKey)
	}
	if len(i.Address) != 1 || i.Address[0] != "10.0.90.2/29" {
		t.Errorf("iface address wrong: %v", i.Address)
	}

	if len(peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(peers))
	}
	p := peers[0]
	if p.Endpoint != "192.168.10.1:16925" || p.Keepalive != 25 {
		t.Errorf("peer0 wrong: %+v", p)
	}
	if len(p.AllowedIPs) != 2 || p.AllowedIPs[1] != "192.168.201.0/24" {
		t.Errorf("peer0 allowed-ips wrong: %v", p.AllowedIPs)
	}
	// second peer: (none) endpoint -> empty, keepalive off -> 0
	if peers[1].Endpoint != "" || peers[1].Keepalive != 0 {
		t.Errorf("peer1 wrong: %+v", peers[1])
	}

	if len(statuses) != 2 {
		t.Fatalf("statuses = %d, want 2", len(statuses))
	}
	if statuses[0].LatestHandshake == nil || statuses[0].RxBytes != 123456 || statuses[0].TxBytes != 654321 {
		t.Errorf("status0 wrong: %+v", statuses[0])
	}
	if statuses[1].LatestHandshake != nil { // handshake 0 -> nil
		t.Errorf("status1 handshake should be nil: %+v", statuses[1])
	}

	// secrets must never survive parsing
	if strings.Contains(strings.Join(fieldsOf(ifaces, peers), " "), "PRIVATEKEY") ||
		strings.Contains(strings.Join(fieldsOf(ifaces, peers), " "), "PRESHAREDKEY") {
		t.Fatal("private/preshared key leaked into parsed structs")
	}
}

func TestWGMermaid(t *testing.T) {
	ifaces := []store.WGInterfaceRow{
		{WGInterface: store.WGInterface{Host: "hub", Iface: "wg0", ListenPort: 51820, PublicKey: "HUBKEY"}},
		{WGInterface: store.WGInterface{Host: "leaf", Iface: "wg0", ListenPort: 51820, PublicKey: "LEAFKEY"}},
	}
	peers := []store.WGPeerRow{
		{WGPeer: store.WGPeer{Host: "hub", Iface: "wg0", PeerPubKey: "LEAFKEY", AllowedIPs: []string{"10.0.0.2/32"}}},
		{WGPeer: store.WGPeer{Host: "leaf", Iface: "wg0", PeerPubKey: "HUBKEY", AllowedIPs: []string{"10.0.0.1/32"}}},
		{WGPeer: store.WGPeer{Host: "hub", Iface: "wg0", PeerPubKey: "EXTKEY", Endpoint: "1.2.3.4:51820", AllowedIPs: []string{"10.3.0.0/24"}}},
	}
	out := wgMermaid(ifaces, peers)

	for _, want := range []string{"graph LR", `subgraph hub["hub"]`, `subgraph leaf["leaf"]`, `hub_wg0["wg0 :51820"]`} {
		if !strings.Contains(out, want) {
			t.Errorf("mermaid missing %q\n%s", want, out)
		}
	}
	// resolved edge appears exactly once (bidirectional collapse): only one
	// edge should point into leaf_wg0, and leaf must not emit its reverse edge.
	if c := strings.Count(out, "| leaf_wg0"); c != 1 {
		t.Errorf("expected exactly one edge into leaf_wg0, got %d\n%s", c, out)
	}
	// external node defined with endpoint label + edge to it
	if !strings.Contains(out, `1.2.3.4:51820`) || !strings.Contains(out, "ext_") {
		t.Errorf("external node/edge missing\n%s", out)
	}
}

func fieldsOf(ifaces []store.WGInterface, peers []store.WGPeer) []string {
	var out []string
	for _, i := range ifaces {
		out = append(out, i.PublicKey, i.Iface)
	}
	for _, p := range peers {
		out = append(out, p.PeerPubKey, p.Endpoint, strings.Join(p.AllowedIPs, ","))
	}
	return out
}
