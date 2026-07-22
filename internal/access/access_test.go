package access

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/sshc"
	"github.com/ghdwlsgur/vctl/internal/store"
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

func TestHostKeyPolicyAppliesToJumpChain(t *testing.T) {
	cases := []struct {
		policy      HostKeyPolicy
		wantConfirm bool
		wantAutoAdd bool
	}{
		{HostKeyPrompt, true, false},
		{HostKeyStrict, false, false},
		{HostKeyAcceptNew, false, true},
	}
	for _, tc := range cases {
		target := &sshc.Target{Jump: &sshc.Target{Jump: &sshc.Target{}}}
		tc.policy.apply(target)
		for hop := target; hop != nil; hop = hop.Jump {
			if hop.ConfirmHostKey != tc.wantConfirm || hop.AutoAddHostKey != tc.wantAutoAdd {
				t.Fatalf("policy %d hop = {confirm:%v autoadd:%v}, want {%v %v}",
					tc.policy, hop.ConfirmHostKey, hop.AutoAddHostKey, tc.wantConfirm, tc.wantAutoAdd)
			}
		}
	}
}

// fakeInv is a minimal Inventory for BuildTarget/ResolveServer.
type fakeInv struct {
	byName  map[string]*store.Server
	resolve func(query string) (*store.Server, []store.Server, error)
}

func (f fakeInv) Resolve(_ context.Context, q string) (*store.Server, []store.Server, error) {
	return f.resolve(q)
}
func (f fakeInv) Get(_ context.Context, host string) (*store.Server, error) {
	sv, ok := f.byName[host]
	if !ok {
		return nil, errors.New("not found: " + host)
	}
	return sv, nil
}

func TestResolveServerAmbiguousListsCandidates(t *testing.T) {
	inv := fakeInv{resolve: func(string) (*store.Server, []store.Server, error) {
		return nil, []store.Server{{Hostname: "app01"}, {Hostname: "app02"}}, nil
	}}
	_, err := ResolveServer(context.Background(), inv, "app")
	if err == nil || !strings.Contains(err.Error(), "ambiguous") || !strings.Contains(err.Error(), "app01") {
		t.Fatalf("ResolveServer ambiguous = %v, want ambiguous+candidates", err)
	}
}

func TestBuildTargetChainAndCycle(t *testing.T) {
	inv := fakeInv{byName: map[string]*store.Server{
		"bastion": {Hostname: "bastion", IP: "10.0.0.1", Port: 22, User: "ops", CARole: "core"},
	}}
	sv := &store.Server{Hostname: "app01", IP: "10.0.0.10", Port: 22, User: "ubuntu", CARole: "core", JumpVia: "bastion"}
	tgt, err := BuildTarget(context.Background(), inv, sv, true)
	if err != nil {
		t.Fatalf("BuildTarget: %v", err)
	}
	if tgt.Addr != "10.0.0.10:22" || tgt.SkipDirect {
		t.Fatalf("target = %+v, want addr set and SkipDirect false (directFirst)", tgt)
	}
	if tgt.Jump == nil || tgt.Jump.Name != "bastion" {
		t.Fatalf("jump chain = %+v, want bastion hop", tgt.Jump)
	}

	// A host that jumps to itself must be caught, not recursed forever.
	cyc := fakeInv{byName: map[string]*store.Server{
		"loop": {Hostname: "loop", IP: "10.0.0.9", Port: 22, JumpVia: "loop"},
	}}
	if _, err := BuildTarget(context.Background(), cyc, cyc.byName["loop"], true); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("BuildTarget cycle = %v, want cycle error", err)
	}
}

// fakes for Connector: assert the audit path always fires.
type fakeSigner struct{ err error }

func (f fakeSigner) SignSSH(context.Context, string, string, []string, string, []string) (string, error) {
	return "", f.err
}

type fakeID struct{ id string }

func (f fakeID) Identity(context.Context) string { return f.id }

type recordingAudit struct {
	entries []store.AccessEntry
	err     error
}

func (r *recordingAudit) LogAccess(_ context.Context, e store.AccessEntry) error {
	r.entries = append(r.entries, e)
	return r.err
}

// TestConnectAuditsFailedConnection proves the locality win: even when the dial
// fails (here, signing errors so no real network is touched), exactly one audit
// row is recorded and it is marked not-OK with the caller's identity.
func TestConnectAuditsFailedConnection(t *testing.T) {
	audit := &recordingAudit{}
	c := &Connector{
		Signer:   fakeSigner{err: errors.New("sign refused")},
		Identity: fakeID{id: "userpass-bob"},
		Audit:    audit,
		SignTTL:  "30m",
	}
	tgt := &sshc.Target{Name: "app01", Addr: "10.0.0.10:22", Role: "core"}
	err := c.Connect(context.Background(), Request{Target: tgt, HostKey: HostKeyPrompt})
	if err == nil {
		t.Fatal("Connect err = nil, want dial failure")
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1", len(audit.entries))
	}
	e := audit.entries[0]
	if e.OK || e.VaultUser != "userpass-bob" || e.Hostname != "app01" || e.Error == "" {
		t.Fatalf("audit entry = %+v, want failed row for bob@app01", e)
	}
	// Host-key policy must have been applied to the target.
	if !tgt.ConfirmHostKey {
		t.Fatal("HostKeyPrompt was not applied to the target")
	}
}

// TestOnAuditErrorSurfacedNotFatal shows an audit-write failure is reported to
// the caller but never masks the connection outcome.
func TestOnAuditErrorSurfacedNotFatal(t *testing.T) {
	var surfaced error
	c := &Connector{
		Signer:       fakeSigner{err: errors.New("sign refused")},
		Identity:     fakeID{id: "bob"},
		Audit:        &recordingAudit{err: errors.New("db down")},
		SignTTL:      "30m",
		OnAuditError: func(err error) { surfaced = err },
	}
	err := c.Connect(context.Background(), Request{Target: &sshc.Target{Name: "h"}, HostKey: HostKeyStrict})
	if err == nil || strings.Contains(err.Error(), "db down") {
		t.Fatalf("Connect err = %v, want the dial error, not the audit error", err)
	}
	if surfaced == nil || !strings.Contains(surfaced.Error(), "db down") {
		t.Fatalf("OnAuditError surfaced = %v, want the audit-write error", surfaced)
	}
}
