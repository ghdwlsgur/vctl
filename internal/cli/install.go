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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	deploynode "github.com/ghdwlsgur/vctl/deploy/node"
	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// installCmd wires the flags for `vctl install`; the work is runInstall.
func installCmd(env cmdkit.Env) *cobra.Command {
	var opts installOptions
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
			return runInstall(cmd, env, args[0], opts)
		},
	}
	cmd.Flags().StringVar(&opts.binPath, "binary", "", "push this local vctl-agent binary instead of downloading the release")
	cmd.Flags().BoolVar(&opts.motd, "motd", true, "render the /etc/motd login banner from inventory topology")
	return cmd
}

type installOptions struct {
	binPath string
	motd    bool
}

// runInstall puts the node-agent on an inventory host over a Vault-signed SSH
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
// the hosts that need this most are the ones without outbound internet. Every
// remote step goes through access.Connector, so each connection leaves the
// same audit row a `vctl ssh` would.
func runInstall(cmd *cobra.Command, env cmdkit.Env, arg string, opts installOptions) error {
	ctx := cmd.Context()
	a, err := env.App()
	if err != nil {
		return err
	}
	if err := a.EnsureLogin(ctx); err != nil {
		return err
	}

	sv, err := installTarget(ctx, a, arg)
	if err != nil {
		return err
	}
	if sv.User != "root" {
		return fmt.Errorf("install needs a root login; inventory user for %s is %q (set it with vctl edit)", sv.Hostname, sv.User)
	}

	// Credentials before the download: minting them is a quick Vault
	// round trip that fails for anyone without the admin grant, and
	// that person should not sit through a multi-MB download first.
	ui.Infof(os.Stderr, "provisioning AppRole credentials (role %s)", nodeAppRole)
	roleID, err := a.Vault.AppRoleRoleID(ctx, a.Cfg.AppRoleMount, nodeAppRole)
	if err != nil {
		return fmt.Errorf("role_id for %s: %w (an admin grant is required to mint agent credentials)", nodeAppRole, err)
	}
	secretID, accessor, err := a.Vault.GenerateSecretIDWithAccessor(ctx, a.Cfg.AppRoleMount, nodeAppRole)
	if err != nil {
		return fmt.Errorf("secret_id for %s: %w", nodeAppRole, err)
	}

	bin, err := agentBinary(ctx, opts.binPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	shaHex := hex.EncodeToString(sum[:])
	ui.Infof(os.Stderr, "agent binary ready (%d bytes, sha256 %s…)", len(bin), shaHex[:12])

	conn := cmdkit.NewConnector(a)
	req := access.Request{
		Target: &sshc.Target{
			Name: sv.Hostname,
			Addr: net.JoinHostPort(sv.IP, installPort(sv)),
			User: sv.User,
			Role: a.Cfg.CARole,
		},
		HostKey: access.HostKeyAcceptNew,
	}

	ui.Infof(os.Stderr, "pushing binary to %s", req.Target.Addr)
	pushCmd := fmt.Sprintf(
		"umask 022 && cat > /usr/local/bin/.vctl-agent.new && chmod 0755 /usr/local/bin/.vctl-agent.new"+
			" && echo '%s  /usr/local/bin/.vctl-agent.new' | sha256sum -c - >/dev/null"+
			" && mv -f /usr/local/bin/.vctl-agent.new /usr/local/bin/vctl-agent", shaHex)
	if err := execStep(conn.ExecuteWithInput(ctx, req, pushCmd, 0, bytes.NewReader(bin))); err != nil {
		return fmt.Errorf("binary push: %w", err)
	}

	ui.Infof(os.Stderr, "installing credentials and systemd units")
	script := installScript(roleID, secretID, accessor, sv.Hostname, opts.motd, controlPlanePins(a))
	if err := execStep(conn.ExecuteWithInput(ctx, req, "sh", 0, strings.NewReader(script))); err != nil {
		return fmt.Errorf("remote install: %w (check journalctl -u vctl-node-agent on the host)", err)
	}
	ui.Successf(os.Stderr, "node-agent running on %s — the heartbeat lands in vctl list within ~5m", sv.Hostname)
	return nil
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
	sv, err := access.ResolveServer(ctx, st, arg)
	if err != nil {
		return nil, fmt.Errorf("%w — the agent reports under the inventory name, so register the host first (vctl add)", err)
	}
	return sv, nil
}

func installPort(sv *store.Server) string {
	if sv.Port > 0 {
		return strconv.Itoa(sv.Port)
	}
	return "22"
}

// execStep turns one remote step's outcome into an error carrying the remote
// stderr — the ansible-equivalent of a failed task, where the far side's words
// matter more than the exit code.
func execStep(res access.Result, err error) error {
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("exit %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return nil
}

// hostPin is one control-plane name and the address the workstation resolved
// for it.
type hostPin struct {
	IP   string
	Name string
}

// controlPlanePins resolves the control-plane names the agent must reach —
// the Vault address and the inventory database — on the workstation.
//
// The agent's first act is reaching Vault, and a fresh host with only public
// DNS cannot resolve internal names. Measured twice in one day: an agent
// `active` with every report ending "lookup vault.sre.local on 8.8.8.8:53: no
// such host", and a second host that resolved Vault (an old hosts entry) but
// not the database. The workstation running install has just proven it CAN
// resolve these — EnsureLogin succeeded — so the answer is carried across.
func controlPlanePins(a *app.App) []hostPin {
	var pins []hostPin
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
				pins = append(pins, hostPin{IP: addr, Name: h})
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

// installScript writes credentials, units and the hostname drop-in, then
// starts the agent and fails unless it comes up. Secrets travel inside the
// encrypted SSH channel and land in 0600 files — the same shape the ansible
// role produces, so either path can maintain a host the other set up. Heredoc
// sentinels are chosen so no payload can terminate them early (unit files
// contain no VCTL_EOF lines).
func installScript(roleID, secretID, accessor, hostname string, motd bool, pins []hostPin) string {
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
	writeHostPins(&b, pins)
	fmt.Fprintf(&b, "cat > /etc/systemd/system/vctl-node-agent.service <<'VCTL_UNIT_EOF'\n%s\nVCTL_UNIT_EOF\n", strings.TrimRight(deploynode.AgentUnit, "\n"))
	b.WriteString("mkdir -p /etc/systemd/system/vctl-node-agent.service.d\n")
	fmt.Fprintf(&b, "cat > /etc/systemd/system/vctl-node-agent.service.d/10-hostname.conf <<'VCTL_DROPIN_EOF'\n%s\nVCTL_DROPIN_EOF\n", nodeAgentDropIn(hostname, motd))
	if motd {
		// ProtectSystem=strict bind-mounts the banner file; the mount cannot
		// attach to a missing path, and creating it must not truncate an
		// existing banner.
		b.WriteString("[ -f /etc/motd ] || install -m 0644 /dev/null /etc/motd\n")
	}
	// The liveness check rides the same connection: set -e fails the script —
	// and therefore the install — when the agent does not come up.
	b.WriteString("systemctl daemon-reload\nsystemctl enable --now vctl-node-agent\nsystemctl restart vctl-node-agent\n")
	b.WriteString("sleep 2\nsystemctl is-active --quiet vctl-node-agent\n")
	return b.String()
}

// writeHostPins emits the pins as the exact marker block the ansible role's
// blockinfile manages ("# BEGIN/END VCTL AUDIT (vault/postgres)"), so a later
// fleet run takes ownership of the same block instead of stacking a second
// copy. The block is written only when the marker is absent AND some pinned
// name does not resolve — a host with working internal DNS gets nothing.
func writeHostPins(b *strings.Builder, pins []hostPin) {
	if len(pins) == 0 {
		return
	}
	checks := make([]string, 0, len(pins))
	var block strings.Builder
	block.WriteString("# BEGIN VCTL AUDIT (vault/postgres)\n")
	for _, p := range pins {
		checks = append(checks, fmt.Sprintf("! getent hosts '%s' >/dev/null 2>&1", p.Name))
		fmt.Fprintf(&block, "%s %s\n", p.IP, p.Name)
	}
	block.WriteString("# END VCTL AUDIT (vault/postgres)")
	fmt.Fprintf(b,
		"if ! grep -q '# BEGIN VCTL AUDIT (vault/postgres)' /etc/hosts 2>/dev/null && { %s; }; then\ncat >> /etc/hosts <<'VCTL_HOSTS_EOF'\n%s\nVCTL_HOSTS_EOF\nfi\n",
		strings.Join(checks, " || "), block.String())
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

// agentBinary returns the vctl-agent build to push: a local file when the
// operator supplied one, otherwise the GitHub release asset matching this
// CLI's version.
func agentBinary(ctx context.Context, binPath string) ([]byte, error) {
	if binPath != "" {
		return os.ReadFile(binPath)
	}
	ver := strings.TrimPrefix(Version, "v")
	if ver == "" || ver == "dev" {
		return nil, fmt.Errorf("this vctl build has no release version — pass --binary <path>")
	}
	return githubRelease(ver).agent(ctx)
}

// releaseSource fetches the vctl-agent release archive, verified against the
// release's checksums.txt. The workstation downloads and the SSH channel
// delivers — fleet hosts often have no outbound internet, and the ansible role
// ships a staged file for the same reason.
//
// base and cacheDir are fields rather than constants so tests can serve a
// release from httptest and cache into a temp dir; production values come from
// githubRelease.
type releaseSource struct {
	base     string // release URL prefix holding checksums.txt and the archive
	archive  string // archive file name, also the cache key
	cacheDir string // verified archives are kept here; "" disables caching
}

func githubRelease(ver string) releaseSource {
	cacheDir := ""
	if dir, err := os.UserCacheDir(); err == nil {
		cacheDir = filepath.Join(dir, "vctl")
	}
	return releaseSource{
		base:     fmt.Sprintf("https://github.com/ghdwlsgur/vctl/releases/download/v%s", ver),
		archive:  fmt.Sprintf("vctl-agent_%s_linux_amd64.tar.gz", ver),
		cacheDir: cacheDir,
	}
}

// agent returns the extracted vctl-agent binary. The verified archive is
// cached under cacheDir keyed by its name, and a cached copy is re-verified
// against checksums.txt on every use — onboarding N hosts downloads once, and
// a corrupted cache can never be pushed.
func (r releaseSource) agent(ctx context.Context) ([]byte, error) {
	sums, err := httpGet(ctx, r.base+"/checksums.txt")
	if err != nil {
		return nil, fmt.Errorf("checksums.txt: %w", err)
	}
	want := ""
	for _, ln := range strings.Split(string(sums), "\n") {
		if strings.HasSuffix(ln, "  "+r.archive) {
			want = strings.Fields(ln)[0]
			break
		}
	}
	if want == "" {
		return nil, fmt.Errorf("release has no checksum for %s", r.archive)
	}

	cache := ""
	if r.cacheDir != "" {
		cache = filepath.Join(r.cacheDir, r.archive)
		if blob, err := os.ReadFile(cache); err == nil && archiveSumOK(blob, want) {
			return extractAgent(blob)
		}
	}
	ui.Infof(os.Stderr, "downloading %s", r.archive)
	blob, err := httpGet(ctx, r.base+"/"+r.archive)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", r.archive, err)
	}
	if !archiveSumOK(blob, want) {
		return nil, fmt.Errorf("%s does not match the release checksum", r.archive)
	}
	if cache != "" {
		_ = os.MkdirAll(r.cacheDir, 0o755)
		_ = os.WriteFile(cache, blob, 0o644) // best-effort: reuse is an optimisation
	}
	return extractAgent(blob)
}

func archiveSumOK(blob []byte, want string) bool {
	got := sha256.Sum256(blob)
	return hex.EncodeToString(got[:]) == want
}

func httpGet(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
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
