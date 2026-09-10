package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

func TestWGPeerPathFillsPlaceholders(t *testing.T) {
	info := vaultc.TokenInfo{Identity: "someone", EntityID: "0f3c-entity"}
	if got := wgPeerPath("kv/users/{entity}/wg", "", info); got != "kv/users/0f3c-entity/wg" {
		t.Errorf("entity path = %q", got)
	}
	if got := wgPeerPath("kv/people/{identity}/wg", "", info); got != "kv/people/someone/wg" {
		t.Errorf("identity path = %q", got)
	}
	if got := wgPeerPath("kv/users/{entity}/wg", "kv/teams/x/wg-peers/me", info); got != "kv/teams/x/wg-peers/me" {
		t.Errorf("the flag must win: %q", got)
	}
}

func TestParseWGPeerReadsTheSecretShape(t *testing.T) {
	sec := map[string]string{
		// Not key-shaped on purpose: the parser does not validate key material
		// (wgtun does, at Up), and a base64 32-byte literal under a field named
		// private_key is what a secret scanner exists to flag.
		"private_key":     "test-private-key-placeholder",
		"address":         "10.20.0.9/32",
		"peer_public_key": "test-peer-public-key-placeholder",
		"peer_endpoint":   "gw.example.com:51820",
		"allowed_ips":     "10.20.0.0/24, 192.0.2.0/24 198.51.100.7",
		"dns":             "10.20.0.1",
		"mtu":             "1380",
		"peer_name":       "gateway-a",
	}
	p, err := parseWGPeer(sec, "kv/users/x/wg", 25*time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "gateway-a" || p.cfg.Addresses[0].String() != "10.20.0.9" || p.cfg.MTU != 1380 {
		t.Errorf("parsed %+v", p)
	}
	peer := p.cfg.Peers[0]
	if peer.Endpoint != "gw.example.com:51820" || peer.Keepalive != 25*time.Second || len(peer.AllowedIPs) != 3 {
		t.Errorf("peer = %+v", peer)
	}
	// A bare address in allowed_ips is that one host.
	if peer.AllowedIPs[2].String() != "198.51.100.7/32" {
		t.Errorf("bare address became %s", peer.AllowedIPs[2])
	}
	if len(p.cfg.DNS) != 1 || p.cfg.DNS[0].String() != "10.20.0.1" {
		t.Errorf("dns = %v", p.cfg.DNS)
	}
}

// A missing field is named — and never the value of any field.
func TestParseWGPeerNamesTheMissingFieldOnly(t *testing.T) {
	sec := map[string]string{"private_key": "test-private-key-placeholder", "address": "10.20.0.9/32"}
	_, err := parseWGPeer(sec, "kv/users/x/wg", time.Second, false)
	if err == nil || !strings.Contains(err.Error(), "peer_public_key") {
		t.Fatalf("err = %v, want the missing field named", err)
	}
	if strings.Contains(err.Error(), "test-private-key-placeholder") {
		t.Error("a secret value leaked into the error")
	}
	_, err = parseWGPeer(map[string]string{}, "kv/users/x/wg", time.Second, false)
	if err == nil || !strings.Contains(err.Error(), "--init") {
		t.Errorf("an empty secret should point at --init: %v", err)
	}
}

func TestParseForwardsIsSSHDashLShaped(t *testing.T) {
	got, err := parseForwards([]string{"6443:10.20.0.5:6443", "5432:db.example.internal:5432"})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].local != "127.0.0.1:6443" || got[0].target != "10.20.0.5:6443" || got[1].target != "db.example.internal:5432" {
		t.Errorf("forwards = %+v", got)
	}
	for _, bad := range []string{"6443", "notaport:10.0.0.1:1", "6443:nohostport"} {
		if _, err := parseForwards([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
