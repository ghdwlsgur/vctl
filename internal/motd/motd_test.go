package motd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// seoulB mirrors the real farm that prompted the feature: the controller is
// known from the capability probe, and one compute's nova.conf carries a typo
// ("sre-svr-0032"), so the control plane's name for it matched no inventory
// host and landed in GhostNames.
func seoulB() store.FarmTopology {
	return store.FarmTopology{
		DeploymentID: "172.16.0.150:5000",
		DisplayName:  "seoul-b",
		State:        "active",
		Team:         "AI Native Platform",
		SyncedAt:     time.Date(2026, 8, 25, 5, 57, 47, 0, time.UTC),
		GhostNames:   []string{"sre-svr-0032"},
		Members: []store.FarmMember{
			{Hostname: "sre-srv-0025", IP: "192.168.201.52", NovaHostname: "sre-srv-0025", Confidence: "confirmed"},
			{Hostname: "sre-srv-0030", IP: "192.168.201.58", NovaHostname: "sre-srv-0030", Confidence: "confirmed"},
			{Hostname: "sre-srv-0032", IP: "192.168.201.63", Confidence: "local-only"},
			{Hostname: "sre-srv-0058", IP: "192.168.201.53", NovaHostname: "sre-srv-0058", Confidence: "confirmed", Controller: true},
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
  Compute #3 : 192.168.201.63  (sre-srv-0032, nova calls it "sre-svr-0032")

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

// A nova name near no member — or near several — must not be pinned to one by
// guesswork; it surfaces as a warning line instead.
func TestUnclaimableNovaNamesAreWarnedNotGuessed(t *testing.T) {
	f := store.FarmTopology{
		DisplayName: "hybrid-platform-dev:200",
		State:       "active",
		SyncedAt:    time.Date(2026, 8, 25, 2, 12, 0, 0, time.UTC),
		// cm-web is near nothing; sre-gpu03 is one keystroke from BOTH members.
		GhostNames: []string{"cm-web", "sre-gpu03"},
		Members: []store.FarmMember{
			{Hostname: "sre-gpu01", IP: "10.0.0.1"},
			{Hostname: "sre-gpu02", IP: "10.0.0.2"},
		},
	}
	got := Render(Banner{Self: "sre-gpu01"}, []store.FarmTopology{f})
	if !strings.Contains(got, "!! nova reports hosts the inventory does not know: cm-web, sre-gpu03") {
		t.Fatalf("unclaimable names not warned:\n%s", got)
	}
	if strings.Contains(got, "nova calls it") {
		t.Fatalf("an ambiguous name was pinned to a member:\n%s", got)
	}
}

// Nova registers short names ("aio01") where the inventory carries site
// prefixes ("incheon-aio01"); an unmatched name that suffix-matches exactly one
// member is pinned to it.
func TestNovaNamePinsThroughSitePrefix(t *testing.T) {
	f := store.FarmTopology{
		DisplayName: "incheon-main-farm",
		State:       "active",
		SyncedAt:    time.Date(2026, 8, 25, 6, 24, 0, 0, time.UTC),
		GhostNames:  []string{"aio01"},
		Members: []store.FarmMember{
			{Hostname: "incheon-aio01", IP: "192.168.10.11", Controller: true},
			{Hostname: "incheon-gpu01", IP: "192.168.10.14"},
		},
	}
	got := Render(Banner{Self: "incheon-gpu01"}, []store.FarmTopology{f})
	if !strings.Contains(got, `(incheon-aio01, nova calls it "aio01")`) {
		t.Fatalf("prefixed inventory name not pinned to nova's short name:\n%s", got)
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

func TestNearlySame(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"sre-srv-0032", "sre-svr-0032", true},          // adjacent transposition — the real case
		{"sre-srv-0032", "sre-srv-0033", true},          // one substitution
		{"sre-srv-0032", "sre-srv-032", true},           // one deletion
		{"sre-srv-0032", "SRE-SRV-0032.internal", true}, // case + domain
		{"sre-srv-0032", "sre-vrs-0032", false},         // two edits
		{"sre-srv-0032", "cm-web", false},
		{"aio1", "aio01", true}, // one insertion
	}
	for _, c := range cases {
		if got := nearlySame(c.a, c.b); got != c.want {
			t.Errorf("nearlySame(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
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
