package cli

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/config"
)

func TestProxyListenAddrOnlyClaimsLoopbackSocks(t *testing.T) {
	cases := map[string]string{
		"":                             "",
		"socks5://127.0.0.1:1080":      "127.0.0.1:1080",
		"socks5h://localhost:1081":     "localhost:1081",
		"socks5://[::1]:1080":          "[::1]:1080",
		"socks5://127.0.0.1":           "127.0.0.1:1080",
		"socks5://198.51.100.7:1080":   "", // somebody's proxy, not ours to start
		"http://127.0.0.1:3128":        "",
		"socks5://proxy.example.com:1": "",
	}
	for in, want := range cases {
		got, err := proxyListenAddr(in)
		if err != nil || got != want {
			t.Errorf("proxyListenAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := proxyListenAddr("socks5://%zz"); err == nil {
		t.Error("an unparsable proxy-url was accepted")
	}
}

func TestTunnelStateIgnoresADeadProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg", "tunnel.json")
	if _, ok := readTunnelState(path); ok {
		t.Fatal("no file read as a running tunnel")
	}
	live := tunnelState{PID: os.Getpid(), Address: "10.0.100.3", Gateway: "gw", Socks: "127.0.0.1:1"}
	if err := writeTunnelState(path, live); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %o", fi.Mode().Perm())
	}
	if got, ok := readTunnelState(path); !ok || got.Address != "10.0.100.3" {
		t.Fatalf("live state = %+v %v", got, ok)
	}
	if err := writeTunnelState(path, tunnelState{PID: 1 << 22, Address: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := readTunnelState(path); ok {
		t.Error("a state file whose pid is gone read as a running tunnel")
	}
}

// fakeTunnel stands in for the detached child: it listens on the address and
// publishes a state file, with a handshake after a short delay.
func fakeTunnel(t *testing.T, statePath string, handshakeAfter time.Duration) func(stateDir, socks string, idle time.Duration) (int, error) {
	return func(_ string, socks string, idle time.Duration) (int, error) {
		ln, err := net.Listen("tcp", socks)
		if err != nil {
			return 0, err
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		st := tunnelState{PID: os.Getpid(), Socks: socks, Address: "10.0.100.3", Gateway: "gw-test", IdleExit: idle.String()}
		_ = writeTunnelState(statePath, st)
		go func() {
			time.Sleep(handshakeAfter)
			st.LastHandshake = time.Now()
			_ = writeTunnelState(statePath, st)
		}()
		return os.Getpid(), nil
	}
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func TestEnsureTunnelStartsOnlyWhenTheProxyIsSilent(t *testing.T) {
	dir := t.TempDir()
	a := &app.App{Cfg: &config.Config{StateDir: dir}}
	addr := freePort(t)
	spawns := 0
	orig := spawnTunnelFn
	spawnTunnelFn = func(stateDir, socks string, idle time.Duration) (int, error) {
		spawns++
		return fakeTunnel(t, tunnelStatePath(dir), 200*time.Millisecond)(stateDir, socks, idle)
	}
	t.Cleanup(func() { spawnTunnelFn = orig })

	var out bytes.Buffer
	if err := ensureTunnel(context.Background(), a, "socks5://"+addr, &out); err != nil {
		t.Fatalf("first call: %v\n%s", err, out.String())
	}
	if spawns != 1 || !strings.Contains(out.String(), "tunnel up") || !strings.Contains(out.String(), "gw-test") || !strings.Contains(out.String(), "30m") {
		t.Errorf("spawns=%d out=%q", spawns, out.String())
	}
	out.Reset()
	if err := ensureTunnel(context.Background(), a, "socks5://"+addr, &out); err != nil || spawns != 1 || out.Len() != 0 {
		t.Errorf("second call: err=%v spawns=%d out=%q (should be silent and not spawn)", err, spawns, out.String())
	}
	// Not our proxy: nothing to do, nothing said.
	if err := ensureTunnel(context.Background(), a, "socks5://198.51.100.7:1080", &out); err != nil || spawns != 1 || out.Len() != 0 {
		t.Errorf("foreign proxy: err=%v spawns=%d out=%q", err, spawns, out.String())
	}
}

func TestWaitForTunnelNamesTheMissingPiece(t *testing.T) {
	dir := t.TempDir()
	statePath := tunnelStatePath(dir)
	var out bytes.Buffer
	// Nothing listening at all.
	_, err := waitForTunnel(context.Background(), freePort(t), statePath, 400*time.Millisecond, newTunnelProgress(&out))
	if err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Errorf("silent port: %v", err)
	}
	// Listening, but the gateway never answers.
	addr := freePort(t)
	if _, err := fakeTunnel(t, statePath, time.Hour)(dir, addr, 0); err != nil {
		t.Fatal(err)
	}
	_, err = waitForTunnel(context.Background(), addr, statePath, 600*time.Millisecond, newTunnelProgress(&out))
	if err == nil || !strings.Contains(err.Error(), "no handshake") {
		t.Errorf("no handshake: %v", err)
	}
	if !strings.Contains(out.String(), "waiting for the gateway") {
		t.Errorf("progress off a terminal should still say what it waits for: %q", out.String())
	}
}
