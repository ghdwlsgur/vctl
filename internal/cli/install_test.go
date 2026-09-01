package cli

import (
	"os"
	"strings"
	"testing"
)

// The embedded unit and the ansible-shipped unit must be the same file, or a
// host set up by `vctl install` and one set up by the fleet role drift apart
// in resource limits and hardening — the exact class of invisible difference
// the unit's own comments document being burned by. go:embed cannot reach
// deploy/ from this package, so the test does the pinning instead.
func TestNodeAgentUnitMatchesTheDeployFile(t *testing.T) {
	b, err := os.ReadFile("../../deploy/node/vctl-node-agent.service")
	if err != nil {
		t.Fatalf("reading the deploy unit: %v", err)
	}
	if got, want := strings.TrimRight(nodeAgentUnit, "\n"), strings.TrimRight(string(b), "\n"); got != want {
		t.Fatalf("embedded unit differs from deploy/node/vctl-node-agent.service — update the constant in install.go")
	}
}

// The drop-in pins the inventory hostname and, with the banner on, appends
// exactly the writable path the strict sandbox needs.
func TestNodeAgentDropInShape(t *testing.T) {
	d := nodeAgentDropIn("sre-srv-0100", true)
	for _, want := range []string{
		"ExecStart=\n",
		"--hostname 'sre-srv-0100'",
		"--motd /etc/motd",
		"ReadWritePaths=/etc/motd",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("drop-in missing %q:\n%s", want, d)
		}
	}
	plain := nodeAgentDropIn("sre-srv-0100", false)
	if strings.Contains(plain, "motd") || strings.Contains(plain, "ReadWritePaths") {
		t.Errorf("motd remnants in the bannerless drop-in:\n%s", plain)
	}
}

// Credentials land 0600 under a 0700 dir, and the units are written through
// quoted heredocs so nothing in them is shell-expanded.
func TestInstallScriptShape(t *testing.T) {
	s := installScript("rid", "sid", "acc", "sre-srv-0100", true)
	for _, want := range []string{
		"umask 077",
		"chmod 0700 /etc/vctl",
		"printf '%s' 'sid' > /etc/vctl/secret-id",
		"chmod 0600 /etc/vctl/secret-id",
		"printf '%s' 'vctl-node' > /etc/vctl/approle",
		"<<'VCTL_UNIT_EOF'",
		"<<'VCTL_DROPIN_EOF'",
		"[ -f /etc/motd ] || install -m 0644 /dev/null /etc/motd",
		"systemctl enable --now vctl-node-agent",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install script missing %q", want)
		}
	}
}
