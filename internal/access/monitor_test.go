package access

import (
	"context"
	"errors"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/sshc"
)

// flakySigner fails on demand so a poll can be made to fail without a network.
type flakySigner struct{ fail bool }

func (f *flakySigner) SignSSH(context.Context, string, string, []string, string, []string) (string, error) {
	if f.fail {
		return "", errors.New("vault unreachable")
	}
	// A signature that dials nowhere still fails, but at a later stage; the
	// tests below only care whether the poll succeeded, which it never does
	// without a real host. Success is simulated by the recording sink instead.
	return "", errors.New("no host")
}

func monitorFixture(t *testing.T) (*Monitor, *recordingAudit) {
	t.Helper()
	rec := &recordingAudit{}
	c := &Connector{Signer: &flakySigner{}, Identity: fakeID{id: "tester"}, Audit: rec}
	return c.Monitor(), rec
}

// pollN drives shouldRecord directly. Poll itself needs a reachable host to
// produce a success, and what these tests pin down is the recording rule, not
// the SSH transport.
func pollN(m *Monitor, target string, outcomes ...bool) []bool {
	var recorded []bool
	for _, ok := range outcomes {
		recorded = append(recorded, m.shouldRecord(target, ok))
	}
	return recorded
}

// A steady session must not keep writing rows. This is the whole point: three
// gateways polled every 2s were producing ~43k access_log rows a day.
func TestMonitorRecordsFirstPollThenGoesQuiet(t *testing.T) {
	m, _ := monitorFixture(t)
	got := pollN(m, "gw-01", true, true, true, true, true)
	want := []bool{true, false, false, false, false}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("poll %d recorded=%v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}
}

// A session that breaks and comes back should leave exactly two more rows: the
// failure and the recovery. Those are the events worth reading.
func TestMonitorRecordsFailureAndRecovery(t *testing.T) {
	m, _ := monitorFixture(t)
	got := pollN(m, "gw-01", true, true, false, false, false, true, true)
	want := []bool{true, false, true, false, false, true, false}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("poll %d recorded=%v, want %v (full: %v)", i, got[i], want[i], got)
		}
	}
}

// The failure case that motivated this: a lapsed session makes every poll fail.
// Before, each failure wrote a row, tried an audit write that also failed, and
// warned — every 2s per gateway. Now the outage is one row.
func TestMonitorDoesNotRepeatAContinuousOutage(t *testing.T) {
	m, _ := monitorFixture(t)
	outcomes := make([]bool, 200) // ~7 minutes at a 2s interval
	got := pollN(m, "gw-01", outcomes...)

	recorded := 0
	for _, r := range got {
		if r {
			recorded++
		}
	}
	if recorded != 1 {
		t.Fatalf("%d rows for a continuous outage, want 1", recorded)
	}
}

// Targets are independent: one gateway flapping must not silence or trigger
// recording for another.
func TestMonitorTracksTargetsSeparately(t *testing.T) {
	m, _ := monitorFixture(t)

	if !m.shouldRecord("gw-01", true) || !m.shouldRecord("gw-02", true) {
		t.Fatal("first poll against each target should record")
	}
	if m.shouldRecord("gw-01", true) || m.shouldRecord("gw-02", true) {
		t.Fatal("second poll against each target should be quiet")
	}
	if !m.shouldRecord("gw-01", false) {
		t.Fatal("gw-01 failing should record")
	}
	if m.shouldRecord("gw-02", true) {
		t.Fatal("gw-02 was unaffected by gw-01 failing and should stay quiet")
	}
}

// Each monitoring session starts with no history, so the first poll of a new
// session records even if a previous session ended in the same state.
func TestMonitorHandleStartsFresh(t *testing.T) {
	c := &Connector{Signer: &flakySigner{}, Identity: fakeID{id: "tester"}, Audit: &recordingAudit{}}
	first, second := c.Monitor(), c.Monitor()

	if !first.shouldRecord("gw-01", true) {
		t.Fatal("first session should record its first poll")
	}
	if !second.shouldRecord("gw-01", true) {
		t.Fatal("a new session should record its first poll, not inherit state")
	}
}

// Execute must keep auditing every call. Monitor moved the decision for polling
// views; it did not weaken the guarantee for commands someone ran.
func TestExecuteStillAuditsEveryCall(t *testing.T) {
	rec := &recordingAudit{}
	c := &Connector{Signer: &flakySigner{fail: true}, Identity: fakeID{id: "tester"}, Audit: rec}
	tgt := &sshc.Target{Name: "gw-01", Addr: "192.0.2.1:22", User: "ubuntu"}

	for range 3 {
		_, _ = c.Execute(context.Background(), Request{Target: tgt, HostKey: HostKeyAcceptNew}, "true", 0)
	}
	if len(rec.entries) != 3 {
		t.Fatalf("Execute wrote %d audit rows for 3 calls, want 3", len(rec.entries))
	}
	for i, e := range rec.entries {
		if e.OK {
			t.Errorf("row %d marked ok despite a failed run", i)
		}
		if e.Hostname != "gw-01" {
			t.Errorf("row %d hostname = %q", i, e.Hostname)
		}
	}
}

// Poll returns the same Result/error shape as Execute, and the row it does
// write carries the failure text.
func TestMonitorPollWritesTheTransitionRow(t *testing.T) {
	rec := &recordingAudit{}
	c := &Connector{Signer: &flakySigner{fail: true}, Identity: fakeID{id: "tester"}, Audit: rec}
	m := c.Monitor()
	tgt := &sshc.Target{Name: "gw-01", Addr: "192.0.2.1:22", User: "ubuntu"}

	for range 5 {
		if _, err := m.Poll(context.Background(), Request{Target: tgt, HostKey: HostKeyAcceptNew}, "true", 0); err == nil {
			t.Fatal("expected the poll to fail")
		}
	}
	if len(rec.entries) != 1 {
		t.Fatalf("5 failing polls wrote %d rows, want 1", len(rec.entries))
	}
	e := rec.entries[0]
	if e.OK {
		t.Error("the recorded row should reflect the failure")
	}
	if e.Error == "" {
		t.Error("the recorded row should carry the failure text")
	}
	if e.VaultUser != "tester" {
		t.Errorf("VaultUser = %q, want the authenticated identity", e.VaultUser)
	}
}
