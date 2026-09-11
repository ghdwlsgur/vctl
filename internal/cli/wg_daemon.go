package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/securefile"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// A background tunnel is `vctl wg connect` running as its own session with
// its output in a log file — started by hand (`vctl wg connect --background`)
// or on demand by the k8s commands when the proxy a kubeconfig names is not
// answering. While it runs it keeps one file current, StateDir/wg/tunnel.json,
// which is how `vctl wg status`, `vctl wg down` and the on-demand start find
// it. A stale file (its pid gone) counts as no tunnel.

const (
	tunnelIdleDefault  = 30 * time.Minute
	tunnelReadyTimeout = 25 * time.Second
)

// tunnelState is what a running tunnel publishes about itself.
type tunnelState struct {
	PID           int       `json:"pid"`
	Background    bool      `json:"background"`
	Socks         string    `json:"socks,omitempty"`
	Address       string    `json:"address"`
	Gateway       string    `json:"gateway"`
	Endpoint      string    `json:"endpoint"`
	StartedAt     time.Time `json:"started_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	RxBytes       uint64    `json:"rx_bytes"`
	TxBytes       uint64    `json:"tx_bytes"`
	OpenConns     int       `json:"open_conns"`
	IdleExit      string    `json:"idle_exit,omitempty"` // time.Duration text; empty = never
	Log           string    `json:"log,omitempty"`
}

func tunnelDir(stateDir string) string { return filepath.Join(stateDir, "wg") }
func tunnelStatePath(stateDir string) string {
	return filepath.Join(tunnelDir(stateDir), "tunnel.json")
}
func tunnelLogPath(stateDir string) string { return filepath.Join(tunnelDir(stateDir), "connect.log") }

func writeTunnelState(path string, s tunnelState) error {
	if err := securefile.EnsurePrivateDir(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return securefile.WriteAtomic(path, raw, 0o600)
}

// readTunnelState returns the running tunnel's state; ok is false when there
// is none — no file, an unreadable one, or one whose process is gone.
func readTunnelState(path string) (tunnelState, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return tunnelState{}, false
	}
	var s tunnelState
	if json.Unmarshal(raw, &s) != nil || s.PID <= 0 || !processAlive(s.PID) {
		return tunnelState{}, false
	}
	return s, true
}

// socksAnswering is the readiness probe: something accepts on addr.
func socksAnswering(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// proxyListenAddr turns a kubeconfig proxy-url into the local address to
// probe. Only a loopback SOCKS proxy is vctl's to start; anything else is
// somebody's own proxy and yields "".
func proxyListenAddr(proxyURL string) (string, error) {
	if proxyURL == "" {
		return "", nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", fmt.Errorf("proxy %q: %w", proxyURL, err)
	}
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return "", nil
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "1080"
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", nil
	}
	return net.JoinHostPort(host, port), nil
}

// spawnTunnelFn starts the detached tunnel process; a variable so tests can
// stand in a fake that listens instead.
var spawnTunnelFn = spawnTunnelDaemon

// spawnTunnelDaemon runs `vctl wg connect --detached-child` as its own session
// with stdin closed and both outputs on the log file, and returns its pid
// without waiting. The child publishes tunnel.json itself.
func spawnTunnelDaemon(stateDir, socks string, idle time.Duration) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	if err := securefile.EnsurePrivateDir(tunnelDir(stateDir), 0o700); err != nil {
		return 0, err
	}
	logFile, err := os.OpenFile(tunnelLogPath(stateDir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer logFile.Close()
	fmt.Fprintf(logFile, "\n== %s starting in the background (idle-exit %s)\n", time.Now().Format(time.RFC3339), idle)
	child := exec.Command(exe, "wg", "connect", "--detached-child", "--socks", socks, "--idle-exit", idle.String(), "--status-every", "1m")
	child.Stdin = nil
	child.Stdout, child.Stderr = logFile, logFile
	child.SysProcAttr = detachAttr()
	if err := child.Start(); err != nil {
		return 0, err
	}
	pid := child.Process.Pid
	_ = child.Process.Release()
	return pid, nil
}

// tunnelProgress is the one updating line a person sees while the tunnel
// comes up. kubectl passes an exec plugin's stderr through, so this is what
// the first `kubectl get nodes` of the day shows. Off a terminal it is plain
// lines.
type tunnelProgress struct {
	w       io.Writer
	tty     bool
	started time.Time
	phase   string
	frame   int
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func newTunnelProgress(w io.Writer) *tunnelProgress {
	f, ok := w.(*os.File)
	return &tunnelProgress{w: w, tty: ok && term.IsTerminal(int(f.Fd())), started: time.Now()}
}

func (p *tunnelProgress) setPhase(msg string) {
	p.phase = msg
	if p.tty {
		p.tick()
		return
	}
	ui.Infof(p.w, "%s…", msg)
}

func (p *tunnelProgress) tick() {
	if !p.tty {
		return
	}
	p.frame = (p.frame + 1) % len(spinnerFrames)
	fmt.Fprintf(p.w, "\r\033[2K%s %s… %s", ui.Muted(spinnerFrames[p.frame]), p.phase, ui.Muted(time.Since(p.started).Round(100*time.Millisecond).String()))
}

func (p *tunnelProgress) done() {
	if p.tty {
		fmt.Fprint(p.w, "\r\033[2K")
	}
}

// waitForTunnel polls until the proxy answers and the tunnel has had its
// first handshake, or the deadline passes. Both are needed: the port opens
// before the gateway has answered, and a kubectl sent through then would hang.
func waitForTunnel(ctx context.Context, socks, statePath string, timeout time.Duration, prog *tunnelProgress) (tunnelState, error) {
	deadline := time.Now().Add(timeout)
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	portUp := false
	for {
		select {
		case <-ctx.Done():
			return tunnelState{}, ctx.Err()
		case <-t.C:
		}
		if !portUp && socksAnswering(socks) {
			portUp = true
			prog.setPhase("proxy is listening; waiting for the gateway's handshake")
		}
		if portUp {
			if st, ok := readTunnelState(statePath); ok && !st.LastHandshake.IsZero() {
				return st, nil
			}
		}
		if time.Now().After(deadline) {
			if portUp {
				return tunnelState{}, fmt.Errorf("the tunnel is listening on %s but got no handshake in %s — is your public key registered on the gateway? see `vctl wg status`", socks, timeout)
			}
			return tunnelState{}, fmt.Errorf("the tunnel did not start within %s — run `vctl wg connect` in a terminal to see why", timeout)
		}
		prog.tick()
	}
}

// ensureTunnel is the on-demand start: when the loopback SOCKS proxy a
// kubeconfig routes a cluster through is not answering, start the tunnel in
// the background, wait for its handshake, and say so on w. Silent when the
// proxy already answers — every call after the first.
func ensureTunnel(ctx context.Context, a *app.App, proxyURL string, w io.Writer) error {
	addr, err := proxyListenAddr(proxyURL)
	if err != nil || addr == "" {
		return err
	}
	if socksAnswering(addr) {
		return nil
	}
	statePath := tunnelStatePath(a.Cfg.StateDir)
	prog := newTunnelProgress(w)
	prog.setPhase(fmt.Sprintf("fleet tunnel is not up — starting vctl wg connect in the background on %s", addr))
	if st, ok := readTunnelState(statePath); !ok || !socksAnswering(st.Socks) {
		if _, err := spawnTunnelFn(a.Cfg.StateDir, addr, tunnelIdleDefault); err != nil {
			prog.done()
			return fmt.Errorf("start the tunnel: %w", err)
		}
	}
	st, err := waitForTunnel(ctx, addr, statePath, tunnelReadyTimeout, prog)
	prog.done()
	if err != nil {
		return fmt.Errorf("%w (log: %s)", err, tunnelLogPath(a.Cfg.StateDir))
	}
	idle := st.IdleExit
	if idle == "" {
		idle = "never"
	}
	ui.Successf(w, "tunnel up in %s: %s via %s · idles out after %s · `vctl wg status`, `vctl wg down`",
		time.Since(prog.started).Round(100*time.Millisecond), st.Address, st.Gateway, idle)
	return nil
}
