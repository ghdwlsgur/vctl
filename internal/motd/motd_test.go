package motd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func seoulB() store.FarmTopology {
	return store.FarmTopology{
		DeploymentID: "172.16.0.150:5000",
		DisplayName:  "seoul-b",
		State:        "active",
		Team:         "AI Native Platform",
		SyncedAt:     time.Date(2026, 8, 25, 5, 57, 47, 0, time.UTC),
		ControlNames: []string{"sre-srv-0058"},
		Members: []store.FarmMember{
			{Hostname: "sre-srv-0025", IP: "192.168.201.52", NovaHostname: "sre-srv-0025", Confidence: "confirmed"},
			{Hostname: "sre-srv-0030", IP: "192.168.201.58", NovaHostname: "sre-srv-0030", Confidence: "confirmed"},
			{Hostname: "sre-srv-0058", IP: "192.168.201.53", NovaHostname: "sre-srv-0058", Confidence: "confirmed"},
		},
	}
}

func TestRenderIsTheWholeBanner(t *testing.T) {
	got := Render(Banner{
		Header:    "== ART ==",
		ManagedBy: "Managed by Innogrid SRE Team.",
		Self:      "sre-srv-0025",
	}, []store.FarmTopology{seoulB()})

	want := `== ART ==

This server is an OpenStack Compute Node.
Managed by Innogrid SRE Team.
Used by AI Native Platform team.

[ Cluster Topology — seoul-b ]
  Controller : 192.168.201.53  (sre-srv-0058)
  Compute #1 : 192.168.201.52  (sre-srv-0025)  <- HERE
  Compute #2 : 192.168.201.58  (sre-srv-0030)

Last synced: 2026-08-25 05:57:47 UTC
`
	if got != want {
		t.Fatalf("banner mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// The machine the banner is on is the controller: the role line follows.
func TestControllerGetsTheControllerRoleLine(t *testing.T) {
	got := Render(Banner{Self: "sre-srv-0058"}, []store.FarmTopology{seoulB()})
	if !strings.Contains(got, "This server is an OpenStack Controller Node.") {
		t.Fatalf("controller not described as one:\n%s", got)
	}
	if !strings.Contains(got, "(sre-srv-0058)  <- HERE") {
		t.Fatalf("HERE marker missing from the controller row:\n%s", got)
	}
}

// No farm, no banner. "" is the contract that keeps the agent from claiming
// /etc/motd on machines this code knows nothing about.
func TestNoFarmRendersNothing(t *testing.T) {
	if got := Render(Banner{Header: "art", Self: "x"}, nil); got != "" {
		t.Fatalf("expected empty render, got:\n%s", got)
	}
}

// The control plane on the farm that prompted this reports a name with a typo
// in it ("sre-svr-…" for a machine the inventory calls "sre-srv-…"). The name
// matches no inventory host, and the banner's job is to show that, not drop it.
func TestUnmatchedControlNameIsShownRaw(t *testing.T) {
	f := seoulB()
	f.ControlNames = []string{"sre-svr-0032"}
	got := Render(Banner{Self: "sre-srv-0025"}, []store.FarmTopology{f})
	if !strings.Contains(got, "sre-svr-0032 (control plane name, not in inventory)") {
		t.Fatalf("typo'd control name dropped instead of shown:\n%s", got)
	}
	// Nobody matched it, so every member renders as a compute.
	if !strings.Contains(got, "Compute #3") {
		t.Fatalf("members should all be computes when no controller matches:\n%s", got)
	}
}

// Nova registers short names ("aio01") where the inventory carries site
// prefixes ("incheon-aio01"); the pairing must survive that.
func TestControlNameMatchesThroughSitePrefix(t *testing.T) {
	f := store.FarmTopology{
		DisplayName:  "incheon-main-farm",
		State:        "active",
		SyncedAt:     time.Date(2026, 8, 25, 6, 24, 0, 0, time.UTC),
		ControlNames: []string{"aio01"},
		Members: []store.FarmMember{
			{Hostname: "incheon-aio01", IP: "192.168.10.11", Confidence: "confirmed"},
			{Hostname: "incheon-gpu01", IP: "192.168.10.14", Confidence: "confirmed"},
		},
	}
	got := Render(Banner{Self: "incheon-gpu01"}, []store.FarmTopology{f})
	if !strings.Contains(got, "Controller : 192.168.10.11  (incheon-aio01)") {
		t.Fatalf("prefixed inventory name not paired with nova's short name:\n%s", got)
	}
}

func TestBrokenFarmSaysSo(t *testing.T) {
	f := seoulB()
	f.State = "broken"
	f.StateNote = "nova 500"
	got := Render(Banner{Self: "sre-srv-0025"}, []store.FarmTopology{f})
	if !strings.Contains(got, "!! farm state is broken: nova 500") {
		t.Fatalf("broken farm rendered as healthy:\n%s", got)
	}
}

// Under ProtectSystem=strict the directory is read-only and only the banner
// file itself is writable (ReadWritePaths) — CreateTemp fails, and Sync must
// fall back to writing the file in place instead of giving up.
func TestSyncFallsBackWhenTheDirectoryIsReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not bind root")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "motd")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	changed, err := Sync(path, "new banner\n")
	if err != nil || !changed {
		t.Fatalf("fallback write: changed=%v err=%v", changed, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new banner\n" {
		t.Fatalf("content = %q", b)
	}
}

func TestSyncWritesOnceAndOnlyOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "motd")

	changed, err := Sync(path, "banner v1\n")
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("motd must be world-readable for pam_motd, got %v", st.Mode().Perm())
	}

	changed, err = Sync(path, "banner v1\n")
	if err != nil || changed {
		t.Fatalf("identical content must not rewrite: changed=%v err=%v", changed, err)
	}

	changed, err = Sync(path, "banner v2\n")
	if err != nil || !changed {
		t.Fatalf("new content: changed=%v err=%v", changed, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "banner v2\n" {
		t.Fatalf("content = %q", b)
	}
	// The temp file must not survive the rename.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("leftover files beside the motd: %v", entries)
	}
}
