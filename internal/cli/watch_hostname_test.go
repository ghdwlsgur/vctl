package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// recordingSessionStore keeps what was written so a test can assert on the name
// the session was filed under.
type recordingSessionStore struct {
	got []store.AuditSession
}

func (r *recordingSessionStore) RecordSession(_ context.Context, a store.AuditSession) (int64, error) {
	r.got = append(r.got, a)
	return int64(len(r.got)), nil
}

func (*recordingSessionStore) EndSession(context.Context, int64, time.Time, string) error {
	return nil
}

func writeMarker(t *testing.T, dir, name string, m sessionMarker) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The PAM stamper can only know the OS hostname, which on this fleet is the
// short name (aio01) while the inventory key is prefixed (incheon-aio01). Audit
// rows filed under the short name join to nothing, so the override has to win.
func TestScanMarkersRecordsUnderHostnameOverride(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, "a.json", sessionMarker{
		Serial: "12363068284355839428", Login: "root", RHost: "192.0.2.10:54321",
		LeaderPID: 1, Host: "aio01", Started: time.Now().UTC().Format(time.RFC3339),
	})

	st := &recordingSessionStore{}
	if err := scanMarkers(context.Background(), st, dir, "incheon-aio01", map[string]int64{}); err != nil {
		t.Fatalf("scanMarkers: %v", err)
	}
	if len(st.got) != 1 {
		t.Fatalf("recorded %d sessions, want 1", len(st.got))
	}
	if st.got[0].Hostname != "incheon-aio01" {
		t.Fatalf("hostname = %q, want the override %q", st.got[0].Hostname, "incheon-aio01")
	}
}

// With no override the marker's own hostname is authoritative — hosts whose OS
// name already matches inventory must keep working untouched.
func TestScanMarkersKeepsMarkerHostnameWithoutOverride(t *testing.T) {
	dir := t.TempDir()
	writeMarker(t, dir, "a.json", sessionMarker{
		Serial: "999", Login: "root", RHost: "192.0.2.11:22",
		LeaderPID: 1, Host: "sre-srv-0047", Started: time.Now().UTC().Format(time.RFC3339),
	})

	st := &recordingSessionStore{}
	if err := scanMarkers(context.Background(), st, dir, "", map[string]int64{}); err != nil {
		t.Fatalf("scanMarkers: %v", err)
	}
	if st.got[0].Hostname != "sre-srv-0047" {
		t.Fatalf("hostname = %q, want the marker's %q", st.got[0].Hostname, "sre-srv-0047")
	}
}

// The reconciler looks up un-ended sessions by hostname. If it resolved a
// different name than the recorder used, stale rows would stay "live" forever —
// so both must go through this one function.
func TestReportedHostnamePrefersOverride(t *testing.T) {
	got, err := reportedHostname("incheon-aio01")
	if err != nil {
		t.Fatal(err)
	}
	if got != "incheon-aio01" {
		t.Fatalf("got %q, want the override", got)
	}

	osName, err := os.Hostname()
	if err != nil {
		t.Skip("os.Hostname unavailable")
	}
	got, err = reportedHostname("")
	if err != nil {
		t.Fatal(err)
	}
	if got != osName {
		t.Fatalf("got %q, want os hostname %q", got, osName)
	}
}
