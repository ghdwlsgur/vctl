package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// installCmd puts the node-agent on an inventory host over a Vault-signed SSH
// connection: the agent binary, its AppRole credentials, and the systemd units,
// then starts it and confirms it is running.
//
// It is the single-host, on-demand form of what deploy/ansible does for the
// fleet. The fleet path stays authoritative for waves and for the audit stack;
// this exists for the host that just joined the inventory — the operator has
// run `vctl inject`, sees "no-agent" in the listing, and should not need an
// ansible checkout to fix that.
//
// The workstation downloads the release binary and pushes it over SSH, because
// the hosts that need this most are the ones without outbound internet.
func installCmd(env CommandEnv) *cobra.Command {
	var (
		binPath string
		motd    bool
	)
	cmd := &cobra.Command{
		Use:   "install [host]",
		Short: "Install the node-agent on an inventory host (binary, AppRole creds, systemd unit)",
		Long: `install onboards an inventory host to run vctl-node-agent.

Over a Vault-certificate SSH connection (run 'vctl inject <host>' first) it
pushes the vctl-agent release binary matching this CLI's version, provisions
AppRole credentials for the node role, installs the systemd unit pinned to the
host's INVENTORY name, and starts the agent. The heartbeat appears in
'vctl list' within the report interval.

Re-running is safe: the binary and units are replaced, the AppRole secret_id
is rotated, and the agent restarts.

  vctl install sre-srv-0100
  vctl install sre-srv-0100 --motd=false     # skip the /etc/motd banner
  vctl install sre-srv-0100 --binary ./vctl-agent   # push a local build`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.newApp()
			if err != nil {
				return err
			}
			if err := a.EnsureLogin(ctx); err != nil {
				return err
			}

			sv, err := installTarget(ctx, a, args[0])
			if err != nil {
				return err
			}
			if sv.User != "root" {
				return fmt.Errorf("install needs a root login; inventory user for %s is %q (set it with vctl edit)", sv.Hostname, sv.User)
			}

			bin, err := agentBinary(ctx, binPath)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(bin)
			shaHex := hex.EncodeToString(sum[:])
			ui.Infof(os.Stderr, "agent binary ready (%d bytes, sha256 %s…)", len(bin), shaHex[:12])

			ui.Infof(os.Stderr, "provisioning AppRole credentials (role %s)", nodeAppRole)
			roleID, err := a.Vault.AppRoleRoleID(ctx, a.Cfg.AppRoleMount, nodeAppRole)
			if err != nil {
				return fmt.Errorf("role_id for %s: %w (an admin grant is required to mint agent credentials)", nodeAppRole, err)
			}
			secretID, accessor, err := a.Vault.GenerateSecretIDWithAccessor(ctx, a.Cfg.AppRoleMount, nodeAppRole)
			if err != nil {
				return fmt.Errorf("secret_id for %s: %w", nodeAppRole, err)
			}

			target := &sshc.Target{
				Name:           sv.Hostname,
				Addr:           net.JoinHostPort(sv.IP, installPort(sv)),
				User:           sv.User,
				Role:           a.Cfg.CARole,
				AutoAddHostKey: true,
			}
			sign := func(role, publicKey string, principals, extensions []string) (string, error) {
				return a.Vault.SignSSH(ctx, role, publicKey, principals, a.Cfg.SSHSign, extensions)
			}

			ui.Infof(os.Stderr, "pushing binary to %s", target.Addr)
			pushCmd := fmt.Sprintf(
				"umask 022 && cat > /usr/local/bin/.vctl-agent.new && chmod 0755 /usr/local/bin/.vctl-agent.new"+
					" && echo '%s  /usr/local/bin/.vctl-agent.new' | sha256sum -c - >/dev/null"+
					" && mv -f /usr/local/bin/.vctl-agent.new /usr/local/bin/vctl-agent", shaHex)
			if err := installRun(ctx, target, sign, pushCmd, bytes.NewReader(bin)); err != nil {
				return fmt.Errorf("binary push: %w", err)
			}

			ui.Infof(os.Stderr, "installing credentials and systemd units")
			script := installScript(roleID, secretID, accessor, sv.Hostname, motd, controlPlanePins(a))
			if err := installRun(ctx, target, sign, "sh", strings.NewReader(script)); err != nil {
				return fmt.Errorf("remote install: %w", err)
			}

			res, _, err := sshc.Run(ctx, target, sign, "systemctl is-active vctl-node-agent")
			if err != nil || strings.TrimSpace(res.Stdout) != "active" {
				return fmt.Errorf("agent did not come up (state %q): check journalctl -u vctl-node-agent on the host", strings.TrimSpace(res.Stdout))
			}
			ui.Successf(os.Stderr, "node-agent running on %s — the heartbeat lands in vctl list within ~5m", sv.Hostname)
			return nil
		},
	}
	cmd.Flags().StringVar(&binPath, "binary", "", "push this local vctl-agent binary instead of downloading the release")
	cmd.Flags().BoolVar(&motd, "motd", true, "render the /etc/motd login banner from inventory topology")
	return cmd
}

// nodeAppRole is the AppRole the node-agent authenticates as: status reporting
// only, the least-privileged role in the catalog. Deliberately not a config
// knob — the fleet role's name is part of the security design, and a config
// override would let a mistyped value silently mint credentials for a broader
// role.
const nodeAppRole = "vctl-node"

// installTarget resolves the argument strictly against the inventory. An
// unregistered host is refused rather than accepted as user@addr: the agent
// reports under the inventory hostname, and a heartbeat for a name the
// inventory lacks is dropped on the server side — the install would "succeed"
// into a void.
func installTarget(ctx context.Context, a *app.App, arg string) (*store.Server, error) {
	st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	sv, cands, err := st.Resolve(ctx, arg)
	if err != nil {
		return nil, err
	}
	if sv == nil {
		if len(cands) == 1 {
			return &cands[0], nil
		}
		return nil, fmt.Errorf("no single inventory host matches %q — register it first (vctl add), the agent reports under the inventory name", arg)
	}
	return sv, nil
}

func installPort(sv *store.Server) string {
	if sv.Port > 0 {
		return strconv.Itoa(sv.Port)
	}
	return "22"
}

// installRun executes one remote step and turns a non-zero exit into an error
// carrying the remote stderr — the ansible-equivalent of a failed task, where
// the far side's words matter more than the exit code.
func installRun(ctx context.Context, t *sshc.Target, sign sshc.SignFunc, command string, input io.Reader) error {
	res, _, err := sshc.RunWithInput(ctx, t, sign, command, input)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// controlPlanePins resolves the control-plane names the agent must reach —
// the Vault address and the inventory database — on the workstation, and
// returns them as "ip name" lines for /etc/hosts.
//
// The agent's first act is reaching Vault, and a fresh host with only public
// DNS cannot resolve internal names. Measured twice in one day: an agent
// `active` with every report ending "lookup vault.sre.local on 8.8.8.8:53: no
// such host", and a second host that resolved Vault (an old hosts entry) but
// not the database. The workstation running install has just proven it CAN
// resolve these — EnsureLogin succeeded — so the answer is carried across.
// The script applies each pin only where the host itself cannot resolve the
// name, so working internal DNS always wins over a pin that could go stale.
func controlPlanePins(a *app.App) []string {
	var pins []string
	for _, h := range []string{urlHostname(a.Cfg.VaultAddr), a.Cfg.DBHost} {
		if h == "" || net.ParseIP(h) != nil {
			continue
		}
		addrs, err := net.LookupHost(h)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
				pins = append(pins, addr+" "+h)
				break
			}
		}
	}
	return pins
}

// urlHostname is the bare host of a URL, "" when it has none.
func urlHostname(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// agentBinary returns the vctl-agent build to push: a local file when the
// operator supplied one, otherwise the GitHub release asset matching this
// CLI's version, verified against the release's checksums.txt. The workstation
// downloads and the SSH channel delivers — fleet hosts often have no outbound
// internet, and the ansible role ships a staged file for the same reason.
func agentBinary(ctx context.Context, binPath string) ([]byte, error) {
	if binPath != "" {
		return os.ReadFile(binPath)
	}
	ver := strings.TrimPrefix(Version, "v")
	if ver == "" || ver == "dev" {
		return nil, fmt.Errorf("this vctl build has no release version — pass --binary <path>")
	}
	base := fmt.Sprintf("https://github.com/ghdwlsgur/vctl/releases/download/v%s", ver)
	archive := fmt.Sprintf("vctl-agent_%s_linux_amd64.tar.gz", ver)

	ui.Infof(os.Stderr, "downloading %s", archive)
	sums, err := httpGet(ctx, base+"/checksums.txt")
	if err != nil {
		return nil, fmt.Errorf("checksums.txt: %w", err)
	}
	want := ""
	for _, ln := range strings.Split(string(sums), "\n") {
		if strings.HasSuffix(ln, "  "+archive) {
			want = strings.Fields(ln)[0]
			break
		}
	}
	if want == "" {
		return nil, fmt.Errorf("release v%s has no checksum for %s", ver, archive)
	}
	blob, err := httpGet(ctx, base+"/"+archive)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", archive, err)
	}
	got := sha256.Sum256(blob)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("%s does not match the release checksum", archive)
	}
	return extractAgent(blob)
}

func httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// extractAgent pulls the vctl-agent member out of the release tarball.
func extractAgent(targz []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(targz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("vctl-agent not found in the release archive")
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name == "vctl-agent" || strings.HasSuffix(hdr.Name, "/vctl-agent") {
			return io.ReadAll(tr)
		}
	}
}

// installScript writes credentials, units and the hostname drop-in, then
// starts the agent. Secrets travel inside the encrypted SSH channel and land
// in 0600 files — the same shape the ansible role produces, so either path
// can maintain a host the other set up. Heredoc sentinels are chosen so no
// payload can terminate them early (unit files contain no VCTL_EOF lines).
//
// pins are "ip name" lines for the control-plane names the agent must reach,
// each applied only when the host cannot already resolve that name — a host
// with working internal DNS keeps it, and only the one that would fail gets
// the /etc/hosts entry.
func installScript(roleID, secretID, accessor, hostname string, motd bool, pins []string) string {
	var b strings.Builder
	b.WriteString("set -e\numask 077\nmkdir -p /etc/vctl\nchmod 0700 /etc/vctl\n")
	cred := func(path, value string) {
		fmt.Fprintf(&b, "printf '%%s' '%s' > %s\nchmod 0600 %s\n", value, path, path)
	}
	cred("/etc/vctl/role-id", roleID)
	cred("/etc/vctl/secret-id", secretID)
	cred("/etc/vctl/secret-id-accessor", accessor)
	cred("/etc/vctl/approle", nodeAppRole)

	b.WriteString("umask 022\n")
	for _, p := range pins {
		name := p[strings.LastIndexByte(p, ' ')+1:]
		fmt.Fprintf(&b, "getent hosts '%s' >/dev/null 2>&1 || echo '%s' >> /etc/hosts\n", name, p)
	}
	fmt.Fprintf(&b, "cat > /etc/systemd/system/vctl-node-agent.service <<'VCTL_UNIT_EOF'\n%s\nVCTL_UNIT_EOF\n", nodeAgentUnit)
	b.WriteString("mkdir -p /etc/systemd/system/vctl-node-agent.service.d\n")
	fmt.Fprintf(&b, "cat > /etc/systemd/system/vctl-node-agent.service.d/10-hostname.conf <<'VCTL_DROPIN_EOF'\n%s\nVCTL_DROPIN_EOF\n", nodeAgentDropIn(hostname, motd))
	if motd {
		// ProtectSystem=strict bind-mounts the banner file; the mount cannot
		// attach to a missing path, and creating it must not truncate an
		// existing banner.
		b.WriteString("[ -f /etc/motd ] || install -m 0644 /dev/null /etc/motd\n")
	}
	b.WriteString("systemctl daemon-reload\nsystemctl enable --now vctl-node-agent\nsystemctl restart vctl-node-agent\n")
	return b.String()
}

// nodeAgentDropIn pins the agent to the inventory hostname — OS names (e.g.
// k8s-all-01) don't match inventory names (e.g. sre-srv-0023), and the server
// drops heartbeats for names the inventory lacks.
func nodeAgentDropIn(hostname string, motd bool) string {
	motdArg, motdPaths := "", ""
	if motd {
		motdArg = " --motd /etc/motd"
		motdPaths = "\nReadWritePaths=/etc/motd"
	}
	return fmt.Sprintf(`# Managed by vctl install. node-agent reports under the INVENTORY hostname.
[Service]
ExecStart=
ExecStart=/usr/local/bin/vctl-agent node-agent --hostname '%s' --interval 5m%s%s`,
		hostname, motdArg, motdPaths)
}

// nodeAgentUnit mirrors deploy/node/vctl-node-agent.service byte for byte;
// TestNodeAgentUnitMatchesTheDeployFile pins the two together so neither can
// drift without a failing build. Embedded rather than go:embed because the
// deploy tree sits outside this package's embed root.
const nodeAgentUnit = `# Report lightweight host state to vctl's central server_status table.
#
# Install: /etc/systemd/system/vctl-node-agent.service ; systemctl enable --now vctl-node-agent
# Creds:   /etc/vctl/role-id, /etc/vctl/secret-id (AppRole -> vctl-node policy -> vctl-status DB role)
[Unit]
Description=vctl node status agent
After=network-online.target
Wants=network-online.target
# No start rate limit. A rate limit here does not protect anything: RestartSec
# already spaces the retries, and the only effect of tripping it is that systemd
# stops trying forever. That is the wrong failure for a status agent, because the
# thing it stops reporting is its own liveness.
#
# 2026-07-29: an upstream Vault outage lasting more than ~3 minutes tripped the
# old 6-per-5min limit on 33 hosts at once. Every one of them latched to ` + "`failed`" + `
# and stayed silent long after Vault recovered — each needed a manual
# ` + "`systemctl reset-failed`" + `. With the limit off the fleet heals itself.
StartLimitIntervalSec=0

[Service]
Environment=VCTL_AUTH_METHOD=approle
Environment=VCTL_ROLE_ID_FILE=/etc/vctl/role-id
Environment=VCTL_SECRET_ID_FILE=/etc/vctl/secret-id
Environment=HOME=/var/lib/vctl
# Match the Go scheduler to the CPU this unit is actually given. Without it the
# runtime sizes itself to every core on the host — 96 on the larger machines
# here — and builds a thread pool for a share of CPU it will never get. Two is
# already generous against CPUQuota=2%.
Environment=GOMAXPROCS=2
ExecStart=/usr/local/bin/vctl-agent node-agent --interval 5m
Restart=always
RestartSec=30
# Restart the agent when its loop stops going round.
#
# Restart=always already covers the agent exiting. It does not cover the agent
# staying up and doing nothing, and that is the failure this fleet actually had:
# a container runtime leaked 16,383 mounts on one host, /proc/self/mountinfo
# reached 2.8MB, and something in the process re-read it forever. The unit sat at
# ` + "`active (running)`" + `, pegged at CPUQuota=2%, and reported nothing for 57 days.
# From systemd's side that is indistinguishable from an idle agent.
#
# The agent pings once per report, inside the loop rather than from a goroutine
# of its own — a separate pinger would keep answering while the loop is wedged,
# which is the state worth catching.
#
# 20m against --interval 5m is three missed reports of headroom. Tight enough to
# catch a hang the same hour, loose enough that a slow Vault or a long DB
# handshake does not restart a working agent. Raising --interval without raising
# this turns the agent into a restart loop; it warns at startup when the two
# cross, because they live in different files.
#
# NotifyAccess is required: it defaults to none for a non-notify service, and
# without it systemd discards the ping and kills the agent every 20 minutes.
# Type stays simple — READY=1 is never sent, so making this Type=notify would
# hang startup instead.
WatchdogSec=20m
NotifyAccess=main
User=root
StateDirectory=vctl
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictSUIDSGID=true
LockPersonality=true
ReadOnlyPaths=/etc/vctl /proc /sys/fs/cgroup /run/systemd
ReadWritePaths=/var/lib/vctl
CPUQuota=2%
MemoryHigh=32M
MemoryMax=48M
# Deliberately unchanged at 24.
#
# On 2026-08-04 the agent hit this and died — not a subprocess, the agent
# itself:
#
#   runtime: failed to create new OS thread (have 25 already; errno=11)
#   fatal error: newosproc
#
# Raising the ceiling was the obvious fix and the wrong one. The ceiling was not
# the problem: an unpinned Go runtime sizes its thread pool to the host's core
# count, so the same agent used 5 threads on most machines and 23 on the 72-core
# ones. GOMAXPROCS above pins it, and those hosts now sit at 5 like everything
# else — measured before and after, same limit:
#
#   without GOMAXPROCS   TasksCurrent=23   (crash loop)
#   with GOMAXPROCS=2    TasksCurrent=5    (no crashes)
#
# So the limit stays where it is. Widening it would have hidden a runtime that
# was sizing itself for CPU this unit is never given, and left nothing to catch
# the next thing that leaks threads.
TasksMax=24
# No core dumps out of this unit, ever.
#
# The probe no longer forks a container engine CLI inside these limits — that is
# what produced "signal: aborted (core dumped)" from both podman and docker on a
# real controller. The guard for that lives in the code and can be regressed;
# this one cannot. A container engine's dump is tens of megabytes written to disk
# on an already-constrained host, and the point of this agent is to be the thing
# on the box that never costs anything.
LimitCORE=0
IOWeight=25
Nice=10
LogRateLimitIntervalSec=30s
LogRateLimitBurst=200

[Install]
WantedBy=multi-user.target`
