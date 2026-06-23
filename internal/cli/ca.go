package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// caCmd manages local trust of the SRE private root CA (the one that signs
// *.sre.local). Installing it into the OS trust store makes browsers and curl
// accept those certs — which also clears HSTS errors, since a valid cert is
// exactly what HSTS requires.
//
// This is distinct from `trust-ca`, which installs the Vault *SSH* CA on a
// remote host so `vctl ssh` works. `ca` is about *TLS* trust on this machine.
func caCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Trust the SRE root CA on this machine (fixes browser/HSTS errors for *.sre.local)",
		Long: `ca manages local trust of the SRE private root CA that signs *.sre.local.

Installing it into the OS trust store lets browsers and curl validate
*.sre.local certificates, which also clears HSTS interstitials (HSTS only
needs a valid cert). The CA is embedded in vctl, so this works offline.

The platform is detected automatically:
  macOS  -> login keychain (per-user; prompts for your password, no sudo)
  Linux  -> system trust store (needs root: 'sudo vctl ca install')
            Debian/Ubuntu: update-ca-certificates
            RHEL/Fedora:   update-ca-trust`,
	}
	cmd.AddCommand(caInstallCmd(), caRemoveCmd(), caPrintCmd())
	return cmd
}

func caInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install the SRE root CA into this machine's trust store",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, cleanup, err := writeTempCA()
			if err != nil {
				return err
			}
			defer cleanup()
			switch runtime.GOOS {
			case "darwin":
				return darwinInstallCA(path)
			case "linux":
				return linuxInstallCA(path)
			default:
				return fmt.Errorf("unsupported platform %q; run 'vctl ca print' and install the CA manually", runtime.GOOS)
			}
		},
	}
}

func caRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove",
		Short: "Remove the SRE root CA trust from this machine",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, cleanup, err := writeTempCA()
			if err != nil {
				return err
			}
			defer cleanup()
			switch runtime.GOOS {
			case "darwin":
				return runVisible("security", "remove-trusted-cert", path)
			case "linux":
				return linuxRemoveCA()
			default:
				return fmt.Errorf("unsupported platform %q", runtime.GOOS)
			}
		},
	}
}

func caPrintCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "print",
		Short: "Print the embedded SRE root CA (PEM) for manual installation",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := os.Stdout.Write(config.SRERootCA)
			return err
		},
	}
}

const caBasename = "innogrid-sre-root-ca.crt"

// writeTempCA materializes the embedded CA to a temp file for the OS tools.
func writeTempCA() (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "vctl-*-"+caBasename)
	if err != nil {
		return "", nil, err
	}
	if _, err := f.Write(config.SRERootCA); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, err
	}
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}

func darwinInstallCA(certPath string) error {
	ui.Infof(os.Stderr, "adding the SRE root CA to your login keychain (you may be prompted for your password)")
	// No -d: writes per-user trust settings in the login keychain (no sudo).
	if err := runVisible("security", "add-trusted-cert", "-r", "trustRoot", certPath); err != nil {
		return fmt.Errorf("security add-trusted-cert: %w", err)
	}
	ui.Successf(os.Stderr, "SRE root CA trusted — restart your browser; *.sre.local should validate (no HSTS error)")
	return nil
}

func linuxInstallCA(certPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("installing into the system trust store needs root; re-run: sudo vctl ca install")
	}
	switch {
	case haveCmd("update-ca-certificates"): // Debian/Ubuntu
		dst := "/usr/local/share/ca-certificates/" + caBasename
		if err := copyFile(certPath, dst, 0o644); err != nil {
			return err
		}
		if err := runVisible("update-ca-certificates"); err != nil {
			return err
		}
	case haveCmd("update-ca-trust"): // RHEL/Fedora
		dst := "/etc/pki/ca-trust/source/anchors/" + caBasename
		if err := copyFile(certPath, dst, 0o644); err != nil {
			return err
		}
		if err := runVisible("update-ca-trust", "extract"); err != nil {
			return err
		}
	default:
		return fmt.Errorf("no supported trust tool found (update-ca-certificates or update-ca-trust)")
	}
	ui.Successf(os.Stderr, "SRE root CA trusted system-wide — *.sre.local should validate (no HSTS error)")
	return nil
}

func linuxRemoveCA() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("removing from the system trust store needs root; re-run: sudo vctl ca remove")
	}
	switch {
	case haveCmd("update-ca-certificates"):
		_ = os.Remove("/usr/local/share/ca-certificates/" + caBasename)
		return runVisible("update-ca-certificates", "--fresh")
	case haveCmd("update-ca-trust"):
		_ = os.Remove("/etc/pki/ca-trust/source/anchors/" + caBasename)
		return runVisible("update-ca-trust", "extract")
	default:
		return fmt.Errorf("no supported trust tool found (update-ca-certificates or update-ca-trust)")
	}
}

func haveCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func runVisible(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
