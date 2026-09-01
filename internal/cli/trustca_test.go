package cli

import (
	"strings"
	"testing"
)

// The destination is the one argument an operator does not type themselves —
// the user half comes from the inventory. It has to land after `--`, where ssh
// stops reading options, or a user of `-oProxyCommand=…` becomes a command run
// on the operator's own machine.
func TestTrustCASSHArgsCloseOptionsBeforeTheDestination(t *testing.T) {
	args := trustCASSHArgs("-oProxyCommand=id@198.51.100.25", "22", "", false)

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

func TestTrustCASSHArgsCarryIdentityPortAndSudo(t *testing.T) {
	args := trustCASSHArgs("root@198.51.100.25", "2222", "/home/op/.ssh/id", true)
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
