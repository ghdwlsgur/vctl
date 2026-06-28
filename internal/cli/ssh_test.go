package cli

import (
	"errors"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/sshc"
)

func TestTruncateAuditError(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'x'
	}
	if got := len(truncateAuditError(string(long))); got != 500 {
		t.Fatalf("len(truncateAuditError) = %d, want 500", got)
	}
}

func TestAccessEntryIncludesConnectionMetadata(t *testing.T) {
	tgt := &sshc.Target{Name: "app01", Addr: "10.0.0.10:22"}
	info := sshc.ConnectionInfo{
		SourceIP:   "192.0.2.10",
		SourceAddr: "192.0.2.10:54321",
		TargetAddr: "10.0.0.10:22",
		JumpHost:   "bastion",
	}
	entry := accessEntry("userpass-albert", tgt, info, "12345", errors.New("connect failed"))
	if entry.OK {
		t.Fatal("OK = true, want false")
	}
	if entry.VaultUser != "userpass-albert" || entry.Hostname != "app01" || entry.CertSerial != "12345" {
		t.Fatalf("entry identity fields = %+v", entry)
	}
	if entry.SourceIP != "192.0.2.10" || entry.SourceAddr != "192.0.2.10:54321" || entry.TargetAddr != "10.0.0.10:22" || entry.JumpVia != "bastion" {
		t.Fatalf("entry connection fields = %+v", entry)
	}
	if entry.Error == "" {
		t.Fatal("Error is empty")
	}
}

func TestSetHostKeyConfirmationAppliesToJumpChain(t *testing.T) {
	target := &sshc.Target{Jump: &sshc.Target{Jump: &sshc.Target{}}}
	setHostKeyConfirmation(target, true)
	for hop := target; hop != nil; hop = hop.Jump {
		if !hop.ConfirmHostKey {
			t.Fatal("host-key confirmation was not applied to every hop")
		}
	}
}
