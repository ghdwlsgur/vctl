package cli

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// injectCmd bootstraps a host to accept vctl's Vault-signed SSH certificates,
// and does not report success until a certificate login has actually worked.
//
// Its predecessor (trust-ca) reported success after installing the CA file and
// passing `sshd -t` — which proves the config parses, not that a certificate
// authenticates. A fresh host with its clock nine hours behind installed
// cleanly, printed OK, and rejected every certificate as "not yet valid"
// (measured on a Rocky 10 host whose RTC held local time read as UTC). The
// command's contract is "after this, vctl ssh works", so the verification has
// to be a real certificate login, and the failure report has to carry the
// server's reason, not the client's guess.
//
// The bootstrap connection uses the operator's normal SSH auth (agent/key/
// password) — not a Vault certificate, which the host does not trust yet.
func injectCmd(env CommandEnv) *cobra.Command {
	var (
		identity string
		useSudo  bool
		port     int
		loginAs  string
		fixClock bool
	)
	cmd := &cobra.Command{
		Use:     "inject [host|user@addr]",
		Aliases: []string{"trust-ca"},
		Short:   "Prepare a host for vctl ssh (install CA trust, then verify a certificate login)",
		Long: `inject onboards a host to accept vctl's Vault-signed SSH certificates.

It fetches the Vault SSH CA public key and, over an ordinary SSH connection
(your agent/key/password — not a Vault cert, which the host does not trust
yet), installs it as TrustedUserCAKeys and reloads sshd. It then verifies the
result the only way that counts: by signing a certificate and logging in with
it. Clock skew beyond what certificate validity tolerates is detected before
the doomed attempt — pass --fix-clock to set the host's clock from this
machine over the same bootstrap connection — and a failed login is followed
up over the bootstrap connection to fetch sshd's own reason.

  vctl inject rnd-gitlab             # resolve user/addr from inventory
  vctl inject root@198.51.100.25     # explicit target (user@addr)
  vctl inject web01 --sudo           # non-root login, escalate for the install`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.newApp()
			if err != nil {
				return err
			}

			user, host, portStr, err := resolveTrustTarget(ctx, a, args[0], loginAs, port)
			if err != nil {
				return err
			}
			// The user may have come from the inventory, which anyone with edit
			// rights can write. It is about to become part of an external ssh
			// argv — see validLoginUser for what a hostile value does there.
			if err := validLoginUser(user); err != nil {
				return err
			}

			if err := a.EnsureLogin(ctx); err != nil {
				return err
			}
			caPub, err := a.Vault.SSHCAPublicKey(ctx)
			if err != nil {
				return err
			}

			dest := user + "@" + host
			ui.Infof(os.Stderr, "installing Vault SSH CA trust on %s (port %s)", dest, portStr)

			sshArgs := injectSSHArgs(dest, portStr, identity, useSudo)

			// The installer also reports the host's clock (first line), so the
			// skew check costs no extra connection — and no extra password
			// prompt when the bootstrap is password-authenticated.
			var out bytes.Buffer
			c := exec.CommandContext(ctx, "ssh", sshArgs...)
			c.Stdin = strings.NewReader(injectScript(caPub))
			c.Stdout = &out
			c.Stderr = os.Stderr
			runErr := c.Run()
			remoteEpoch := printInstallOutput(out.String())
			if runErr != nil {
				return fmt.Errorf("remote install on %s failed: %w", dest, runErr)
			}

			if msg := clockSkewProblem(time.Now(), remoteEpoch); msg != "" {
				if !fixClock {
					ui.Errorf(os.Stderr, "CA trust installed, but %s", msg)
					return fmt.Errorf("certificate login cannot work until the host clock is fixed — re-run with --fix-clock to set it from this machine over the same bootstrap connection")
				}
				// Fresh installs arrive with the RTC in local time and no NTP
				// daemon (measured five times in one onboarding week); the fix
				// is carrying this machine's clock across, exactly what an
				// operator does by hand. A second bootstrap connection — and a
				// second password prompt when that is the auth — is the cost.
				ui.Warnf(os.Stderr, "%s — fixing over the bootstrap connection", msg)
				epoch, hasNTP, err := injectFixClock(ctx, dest, portStr, identity, useSudo)
				if err != nil {
					return fmt.Errorf("clock fix on %s failed: %w", dest, err)
				}
				if msg := clockSkewProblem(time.Now(), epoch); msg != "" {
					return fmt.Errorf("clock still wrong after the fix: %s", msg)
				}
				if !hasNTP {
					ui.Warnf(os.Stderr, "clock set manually and the RTC updated, but the host has no NTP daemon — install chrony so it stays right")
				}
			}

			ui.Infof(os.Stderr, "verifying with a real certificate login as %s", user)
			// Through the connector, not raw sshc: the verification IS an SSH
			// into the host, and every certificate login leaves an audit row —
			// including this one.
			verify := access.Request{
				Target: &sshc.Target{
					Name: args[0],
					Addr: net.JoinHostPort(host, portStr),
					User: user,
					Role: a.Cfg.CARole,
				},
				HostKey: access.HostKeyAcceptNew,
			}
			if err := execStep(newConnector(a).Execute(ctx, verify, "true", 0)); err != nil {
				ui.Errorf(os.Stderr, "certificate login failed: %v", err)
				injectDiagnose(ctx, dest, portStr, identity, useSudo)
				return fmt.Errorf("CA trust installed but a certificate login still fails — see the sshd log above")
			}
			ui.Successf(os.Stderr, "verified — vctl ssh %q works", args[0])
			return nil
		},
	}
	cmd.Flags().StringVarP(&identity, "identity", "i", "", "SSH identity file for the bootstrap connection")
	cmd.Flags().BoolVar(&useSudo, "sudo", false, "use sudo for the remote install (non-root login)")
	cmd.Flags().IntVar(&port, "port", 0, "override SSH port (default: inventory value or 22)")
	cmd.Flags().StringVar(&loginAs, "user", "", "override login user")
	cmd.Flags().BoolVar(&fixClock, "fix-clock", false,
		"when the host clock is too skewed for certificates, set it from this machine's clock over the bootstrap connection")
	return cmd
}

// injectSSHArgs builds the argv for the bootstrap ssh. Options come first and
// `--` closes them, so whatever dest holds is a destination to ssh and never an
// option — the inventory-supplied user in dest is data, not syntax. Without the
// separator a user of `-oProxyCommand=…` would run that command locally.
func injectSSHArgs(dest, portStr, identity string, useSudo bool) []string {
	args := []string{"-p", portStr, "-o", "StrictHostKeyChecking=accept-new"}
	if identity != "" {
		args = append(args, "-i", identity)
	}
	remoteShell := "sh"
	if useSudo {
		remoteShell = "sudo sh"
	}
	return append(args, "--", dest, remoteShell)
}

// printInstallOutput relays the installer's output and extracts the epoch
// marker the script printed, returning 0 when no marker was found (an older
// or tampered remote shell) — callers treat 0 as "unknown, skip the check".
func printInstallOutput(out string) (remoteEpoch int64) {
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(ln, "VCTL_REMOTE_EPOCH="); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				remoteEpoch = n
			}
			continue
		}
		if ln != "" {
			fmt.Fprintln(os.Stdout, ln)
		}
	}
	return remoteEpoch
}

// Vault backdates certificates by 30 seconds, so a host clock behind by more
// than that rejects every certificate as "not yet valid" until it catches up.
// A clock far ahead instead burns the certificate's TTL. Both render the
// install useless, so they are reported as the finding rather than letting the
// verification fail with a bare "permission denied".
const maxCertClockSkew = 30 * time.Second

// clockSkewProblem reports a human-sized description of the skew when it is
// beyond what certificate validation tolerates, and "" when the clock is fine
// or unknown (epoch 0).
func clockSkewProblem(localNow time.Time, remoteEpoch int64) string {
	if remoteEpoch == 0 {
		return ""
	}
	skew := localNow.Sub(time.Unix(remoteEpoch, 0))
	var direction, consequence string
	switch {
	case skew > maxCertClockSkew:
		direction, consequence = "behind", `certificates will be rejected as "not yet valid"`
	case skew < -maxCertClockSkew:
		skew, direction, consequence = -skew, "ahead", "certificates will expire early or be rejected"
	default:
		return ""
	}
	return fmt.Sprintf("the host clock is %s %s — %s. "+
		"Fix time sync first (chronyd, or: timedatectl set-local-rtc 0; date -u -s <now>; hwclock --systohc)",
		skew.Round(time.Second), direction, consequence)
}

// injectFixClock sets the host clock from this machine's over the bootstrap
// connection: RTC interpreted as UTC, time stepped to now, RTC written back,
// and chronyd enabled when the host has it. It reports the host's clock after
// the fix and whether an NTP daemon is now running.
func injectFixClock(ctx context.Context, dest, portStr, identity string, useSudo bool) (epoch int64, hasNTP bool, err error) {
	var out bytes.Buffer
	c := exec.CommandContext(ctx, "ssh", injectSSHArgs(dest, portStr, identity, useSudo)...)
	c.Stdin = strings.NewReader(injectFixClockScript(time.Now()))
	c.Stdout = &out
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return 0, false, err
	}
	for _, ln := range strings.Split(out.String(), "\n") {
		if v, ok := strings.CutPrefix(ln, "VCTL_REMOTE_EPOCH="); ok {
			epoch, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		}
		if strings.TrimSpace(ln) == "VCTL_NTP=yes" {
			hasNTP = true
		}
	}
	return epoch, hasNTP, nil
}

// injectFixClockScript carries the caller's clock across. The timestamp is
// baked in when the script is built; the seconds the connection takes are
// noise against the 30s tolerance certificates actually need.
func injectFixClockScript(now time.Time) string {
	return fmt.Sprintf(`set -e
timedatectl set-local-rtc 0 2>/dev/null || true
date -u -s '%s' >/dev/null
hwclock --systohc 2>/dev/null || true
if command -v chronyd >/dev/null 2>&1; then
  systemctl enable --now chronyd >/dev/null 2>&1 || true
fi
systemctl is-active --quiet chronyd 2>/dev/null && echo VCTL_NTP=yes || echo VCTL_NTP=no
echo "VCTL_REMOTE_EPOCH=$(date -u +%%s)"
`, now.UTC().Format("2006-01-02 15:04:05"))
}

// injectDiagnose fetches sshd's own account of the rejection over the
// bootstrap connection. Best-effort: the operator already has a failure in
// hand; this only adds the server's reason when it can be reached.
func injectDiagnose(ctx context.Context, dest, portStr, identity string, useSudo bool) {
	ui.Infof(os.Stderr, "fetching sshd's reason over the bootstrap connection")
	script := `journalctl -u sshd -u ssh -n 40 --no-pager 2>/dev/null | grep -iE "cert|denied|invalid|error" | tail -5
sshd -T 2>/dev/null | grep -i trusteduserca || echo "sshd -T reports no TrustedUserCAKeys (config not applied?)"`
	c := exec.CommandContext(ctx, "ssh", injectSSHArgs(dest, portStr, identity, useSudo)...)
	c.Stdin = strings.NewReader(script)
	c.Stdout = os.Stderr
	c.Stderr = os.Stderr
	_ = c.Run()
}

// injectScript is the idempotent remote installer, read by `sh` over stdin.
// The CA key is written via a quoted heredoc so no shell expansion touches it.
// The first output line reports the host's clock for the skew check.
func injectScript(caPub string) string {
	return fmt.Sprintf(`set -e
echo "VCTL_REMOTE_EPOCH=$(date -u +%%s)"
CAFILE=/etc/ssh/vault-ca.pub
DROPIN=/etc/ssh/sshd_config.d/10-vault-ca.conf
umask 022
cat > "$CAFILE" <<'VCTL_CA_EOF'
%s
VCTL_CA_EOF
printf 'TrustedUserCAKeys %%s\n' "$CAFILE" > "$DROPIN"
if sshd -t; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || service ssh reload 2>/dev/null || true
  echo "[vctl] CA trust installed at $CAFILE"
else
  echo "[vctl] sshd config invalid; rolled back" >&2
  rm -f "$DROPIN"
  exit 1
fi
`, caPub)
}

// resolveTrustTarget turns the argument into (user, host, port). An explicit
// user@addr (optionally host:port) is used as-is; anything else is looked up in
// the inventory so registered hosts onboard by name.
func resolveTrustTarget(ctx context.Context, a *app.App, arg, loginAs string, port int) (user, host, portStr string, err error) {
	portStr = "22"
	if port > 0 {
		portStr = strconv.Itoa(port)
	}

	// Shared with `vctl ssh`, which now accepts the same form. One parser so the
	// two commands cannot disagree about what "user@host:port" means.
	if ep, ok := parseUserAtAddr(arg); ok {
		user = ep.User
		if loginAs != "" {
			user = loginAs
		}
		if port == 0 {
			portStr = ep.Port
		}
		return user, ep.Host, portStr, nil
	}

	st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
	if err != nil {
		return "", "", "", err
	}
	defer st.Close()

	sv, cands, err := st.Resolve(ctx, arg)
	if err != nil {
		return "", "", "", err
	}
	if sv == nil {
		switch len(cands) {
		case 0:
			return "", "", "", fmt.Errorf("no server matches %q (use user@addr for an unregistered host)", arg)
		case 1:
			sv = &cands[0]
		default:
			names := make([]string, 0, len(cands))
			for _, c := range cands {
				names = append(names, c.Hostname)
			}
			return "", "", "", fmt.Errorf("%q matches multiple hosts: %s", arg, strings.Join(names, ", "))
		}
	}

	user = sv.User
	if loginAs != "" {
		user = loginAs
	}
	if port == 0 && sv.Port > 0 {
		portStr = strconv.Itoa(sv.Port)
	}
	return user, sv.IP, portStr, nil
}
