package cli

import (
	"strings"
	"testing"

	deploynode "github.com/ghdwlsgur/vctl/deploy/node"
)

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

// Credentials land 0600 under a 0700 dir, the units are written through
// quoted heredocs so nothing in them is shell-expanded, and the script itself
// proves the agent came up — set -e turns a dead unit into a failed install.
func TestInstallScriptShape(t *testing.T) {
	s := installScript("rid", "sid", "acc", "sre-srv-0100", true, nil)
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
		"systemctl is-active --quiet vctl-node-agent",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install script missing %q", want)
		}
	}
	// The unit rides in from the deploy tree — one source, no second copy.
	if !strings.Contains(s, strings.TrimRight(deploynode.AgentUnit, "\n")) {
		t.Error("install script does not carry the embedded deploy unit verbatim")
	}
	if strings.Contains(s, "/etc/hosts") {
		t.Error("no pins requested but the script still touches /etc/hosts")
	}
}

// Control-plane pins ride as the exact marker block the ansible role's
// blockinfile manages, so a later fleet run takes ownership of the same block
// instead of stacking a second copy — and only when the marker is absent AND a
// pinned name does not resolve, so working internal DNS wins. Measured twice
// in one day: agents `active` while every report died on "no such host" for
// names only the workstation could resolve.
func TestInstallScriptPinsUseTheAnsibleMarkerBlock(t *testing.T) {
	s := installScript("rid", "sid", "acc", "h", false, []hostPin{
		{IP: "192.0.2.10", Name: "vault.sre.local"},
		{IP: "192.0.2.10", Name: "vctl-postgres.sre.local"},
	})
	for _, want := range []string{
		"grep -q '# BEGIN VCTL AUDIT (vault/postgres)' /etc/hosts",
		"! getent hosts 'vault.sre.local' >/dev/null 2>&1 || ! getent hosts 'vctl-postgres.sre.local' >/dev/null 2>&1",
		"# BEGIN VCTL AUDIT (vault/postgres)\n192.0.2.10 vault.sre.local\n192.0.2.10 vctl-postgres.sre.local\n# END VCTL AUDIT (vault/postgres)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install script missing pin block piece:\n%s", want)
		}
	}
}
