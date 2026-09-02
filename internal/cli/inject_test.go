package cli

import (
	"strings"
	"testing"
	"time"
)

// The destination is the one argument an operator does not type themselves —
// the user half comes from the inventory. It has to land after `--`, where ssh
// stops reading options, or a user of `-oProxyCommand=…` becomes a command run
// on the operator's own machine.
func TestInjectSSHArgsCloseOptionsBeforeTheDestination(t *testing.T) {
	args := injectSSHArgs("-oProxyCommand=id@198.51.100.25", "22", "", false)

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 {
		t.Fatalf("no `--` in %q", args)
	}
	if got := args[sep+1:]; len(got) != 2 || got[0] != "-oProxyCommand=id@198.51.100.25" || got[1] != "sh" {
		t.Fatalf("after `--` = %q, want [dest sh]", got)
	}
	for _, a := range args[:sep] {
		if strings.Contains(a, "@") {
			t.Fatalf("destination %q appears before `--`", a)
		}
	}
}

func TestInjectSSHArgsCarryIdentityPortAndSudo(t *testing.T) {
	args := injectSSHArgs("root@198.51.100.25", "2222", "/home/op/.ssh/id", true)
	want := []string{"-p", "2222", "-o", "StrictHostKeyChecking=accept-new", "-i", "/home/op/.ssh/id", "--", "root@198.51.100.25", "sudo sh"}
	if strings.Join(args, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %q, want %q", args, want)
	}
}

// The separator is the mechanism; the check is what tells the operator why a
// stored value is being refused instead of failing inside ssh.
func TestValidLoginUserRefusesWhatSSHWouldMisread(t *testing.T) {
	for _, bad := range []string{"", "-oProxyCommand=id", "root user", "root\n", "a@b", "a:b", "a/b"} {
		if err := validLoginUser(bad); err == nil {
			t.Errorf("validLoginUser(%q) accepted", bad)
		}
	}
	for _, ok := range []string{"root", "ubuntu", "sre-ops", "svc_backup", "user.name", "Deploy2"} {
		if err := validLoginUser(ok); err != nil {
			t.Errorf("validLoginUser(%q) = %v", ok, err)
		}
	}
}

// The skew check is what turns "permission denied" into a finding. Measured
// origin: a Rocky 10 host whose RTC held KST read as UTC — nine hours behind,
// every certificate "not yet valid", while trust-ca had printed OK.
func TestClockSkewProblemFlagsWhatCertsCannotSurvive(t *testing.T) {
	now := time.Now()
	if msg := clockSkewProblem(now, now.Add(-9*time.Hour).Unix()); !strings.Contains(msg, "behind") {
		t.Errorf("nine hours behind not flagged: %q", msg)
	}
	if msg := clockSkewProblem(now, now.Add(45*time.Minute).Unix()); !strings.Contains(msg, "ahead") {
		t.Errorf("45m ahead not flagged: %q", msg)
	}
	if msg := clockSkewProblem(now, now.Add(-5*time.Second).Unix()); msg != "" {
		t.Errorf("5s skew flagged: %q", msg)
	}
	// Unknown clock (no marker) is not a verdict.
	if msg := clockSkewProblem(now, 0); msg != "" {
		t.Errorf("unknown epoch flagged: %q", msg)
	}
}

// The epoch marker is consumed, everything else is relayed verbatim.
func TestPrintInstallOutputExtractsTheEpochMarker(t *testing.T) {
	out := "VCTL_REMOTE_EPOCH=1756711200\n[vctl] CA trust installed at /etc/ssh/vault-ca.pub\n"
	if got := printInstallOutput(out); got != 1756711200 {
		t.Fatalf("epoch = %d, want 1756711200", got)
	}
}

// The installer script's first output line is the host's clock — the skew
// check rides the bootstrap connection for free — and the CA key travels in a
// quoted heredoc so nothing in it is shell-expanded. The rollback branch keeps
// a broken drop-in from surviving a failed sshd -t.
func TestInjectScriptShape(t *testing.T) {
	s := injectScript("ssh-rsa AAAA-test-ca")
	if !strings.HasPrefix(s, "set -e\necho \"VCTL_REMOTE_EPOCH=$(date -u +%s)\"") {
		t.Fatalf("epoch marker is not the first output:\n%s", s[:80])
	}
	for _, want := range []string{
		"<<'VCTL_CA_EOF'\nssh-rsa AAAA-test-ca\nVCTL_CA_EOF",
		"TrustedUserCAKeys",
		"sshd -t",
		"rm -f \"$DROPIN\"",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("inject script missing %q", want)
		}
	}
}
