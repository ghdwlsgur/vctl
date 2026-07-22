package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// trustCACmd bootstraps a host to accept vctl's Vault-signed SSH certificates.
// It is the one-time onboarding step before `vctl ssh` works against a host:
// it installs the Vault SSH CA public key as TrustedUserCAKeys and reloads sshd.
//
// The bootstrap connection uses the operator's normal SSH auth (agent/key/
// password) — not a Vault certificate, which the host does not trust yet.
func trustCACmd() *cobra.Command {
	var (
		identity string
		useSudo  bool
		port     int
		loginAs  string
	)
	cmd := &cobra.Command{
		Use:   "trust-ca [host|user@addr]",
		Short: "Install Vault SSH CA trust on a host so vctl ssh works",
		Long: `trust-ca onboards a host to accept vctl's Vault-signed SSH certificates.

It fetches the Vault SSH CA public key and, over an ordinary SSH connection
(your agent/key/password — not a Vault cert, which the host does not trust
yet), installs it as TrustedUserCAKeys and reloads sshd. It is idempotent and
validates sshd config before reloading, rolling back on failure.

  vctl trust-ca rnd-gitlab             # resolve user/addr from inventory
  vctl trust-ca root@198.51.100.25     # explicit target (user@addr)
  vctl trust-ca web01 --sudo           # non-root login, escalate for the install`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}

			user, host, portStr, err := resolveTrustTarget(ctx, a, args[0], loginAs, port)
			if err != nil {
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

			sshArgs := []string{"-p", portStr, "-o", "StrictHostKeyChecking=accept-new"}
			if identity != "" {
				sshArgs = append(sshArgs, "-i", identity)
			}
			remoteShell := "sh"
			if useSudo {
				remoteShell = "sudo sh"
			}
			sshArgs = append(sshArgs, dest, remoteShell)

			c := exec.CommandContext(ctx, "ssh", sshArgs...)
			c.Stdin = strings.NewReader(trustCAScript(caPub))
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			if err := c.Run(); err != nil {
				return fmt.Errorf("remote install on %s failed: %w", dest, err)
			}
			ui.Successf(os.Stderr, "CA trust installed — try: vctl ssh %q", args[0])
			return nil
		},
	}
	cmd.Flags().StringVarP(&identity, "identity", "i", "", "SSH identity file for the bootstrap connection")
	cmd.Flags().BoolVar(&useSudo, "sudo", false, "use sudo for the remote install (non-root login)")
	cmd.Flags().IntVar(&port, "port", 0, "override SSH port (default: inventory value or 22)")
	cmd.Flags().StringVar(&loginAs, "user", "", "override login user")
	return cmd
}

// resolveTrustTarget turns the argument into (user, host, port). An explicit
// user@addr (optionally host:port) is used as-is; anything else is looked up in
// the inventory so registered hosts onboard by name.
func resolveTrustTarget(ctx context.Context, a *app.App, arg, loginAs string, port int) (user, host, portStr string, err error) {
	portStr = "22"
	if port > 0 {
		portStr = strconv.Itoa(port)
	}

	if strings.Contains(arg, "@") {
		user = arg[:strings.Index(arg, "@")]
		hostpart := arg[strings.Index(arg, "@")+1:]
		if h, p, e := net.SplitHostPort(hostpart); e == nil {
			hostpart = h
			if port == 0 {
				portStr = p
			}
		}
		if loginAs != "" {
			user = loginAs
		}
		return user, hostpart, portStr, nil
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

// trustCAScript is the idempotent remote installer, read by `sh` over stdin.
// The CA key is written via a quoted heredoc so no shell expansion touches it.
func trustCAScript(caPub string) string {
	return fmt.Sprintf(`set -e
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
