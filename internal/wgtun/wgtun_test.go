package wgtun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Two tunnels in one process, joined over loopback UDP: a "gateway" that
// listens on its tunnel address and echoes, and a client that dials it. No
// kernel interface, no root — which is the whole point of the package.
func TestTwoTunnelsCarryTCP(t *testing.T) {
	gwPriv, gwPub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cliPriv, cliPub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	gwAddr, cliAddr := netip.MustParseAddr("10.200.0.1"), netip.MustParseAddr("10.200.0.2")

	gw, err := Up(Config{
		PrivateKey: gwPriv, Addresses: []netip.Addr{gwAddr},
		Peers: []Peer{{PublicKey: cliPub, AllowedIPs: []netip.Prefix{netip.PrefixFrom(cliAddr, 32)}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	port, err := gw.ListenPort()
	if err != nil || port == 0 {
		t.Fatalf("gateway listen port: %d %v", port, err)
	}
	ln, err := gw.ListenTCP(&net.TCPAddr{IP: gwAddr.AsSlice(), Port: 7000})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	cli, err := Up(Config{
		PrivateKey: cliPriv, Addresses: []netip.Addr{cliAddr},
		Peers: []Peer{{
			PublicKey: gwPub, Endpoint: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.200.0.0/24")}, Keepalive: 5 * time.Second,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := cli.DialContext(ctx, "tcp", "10.200.0.1:7000")
	if err != nil {
		t.Fatalf("dial through the tunnel: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}

	stats, err := cli.Stats()
	if err != nil || len(stats) != 1 {
		t.Fatalf("stats = %+v, %v", stats, err)
	}
	if stats[0].PublicKey != gwPub {
		t.Errorf("peer key = %s, want %s", stats[0].PublicKey, gwPub)
	}
	if stats[0].LastHandshake.IsZero() || stats[0].TxBytes == 0 || stats[0].RxBytes == 0 {
		t.Errorf("no handshake or no traffic recorded: %+v", stats[0])
	}
}

func TestKeysRoundTrip(t *testing.T) {
	priv, pub, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKey(priv)
	if err != nil || got != pub {
		t.Fatalf("PublicKey(priv) = %s, %v; want %s", got, err, pub)
	}
	if _, err := PublicKey("bm90LWEta2V5"); err == nil {
		t.Error("a short key was accepted")
	}
}

// The UAPI form is what the device actually consumes; the fields a wg config
// carries must land there in hex, with the endpoint as a literal address.
func TestUAPIConfigShape(t *testing.T) {
	priv, pub, _ := GenerateKey()
	uapi, err := uapiConfig(Config{
		PrivateKey: priv, Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.2")}, ListenPort: 0,
		Peers: []Peer{{PublicKey: pub, Endpoint: "127.0.0.1:51820", Keepalive: 25 * time.Second,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("192.0.2.7/32")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=", "replace_peers=true", "public_key=", "endpoint=127.0.0.1:51820",
		"persistent_keepalive_interval=25", "allowed_ip=10.0.0.0/24", "allowed_ip=192.0.2.7/32"} {
		if !strings.Contains(uapi, want) {
			t.Errorf("uapi lacks %q:\n%s", want, uapi)
		}
	}
	if strings.Contains(uapi, "listen_port=") {
		t.Error("a client asked for no listen port and got one")
	}
	if _, err := uapiConfig(Config{PrivateKey: priv, Peers: []Peer{{PublicKey: pub}}}); err == nil {
		t.Error("a peer with no allowed IPs was accepted")
	}
}
