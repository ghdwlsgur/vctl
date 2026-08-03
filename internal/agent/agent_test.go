package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/securefile"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

func TestWriteFileAtomicWrites0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token-sink")
	if err := securefile.WriteAtomic(path, []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "token" {
		t.Fatalf("content = %q", string(b))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm = %o, want 600", got)
	}
}

func TestWriteFileAtomicRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token-sink")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := securefile.WriteAtomic(link, []byte("token"), 0o600); err == nil {
		t.Fatal("writeFileAtomic accepted a symlink sink")
	}

	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old" {
		t.Fatalf("target content = %q", string(b))
	}
}

func TestWriteFileAtomicRejectsDirectory(t *testing.T) {
	if err := securefile.WriteAtomic(t.TempDir(), []byte("token"), 0o600); err == nil {
		t.Fatal("writeFileAtomic accepted a directory sink")
	}
}

// renewWait decides when the token is renewed. Both directions of getting it
// wrong are silent: too late and the token expires mid-session, too early and
// the agent hammers Vault for the life of the process. Neither shows up as an
// error, so the arithmetic is pinned here.

// The property that matters more than any single value: the wait must leave
// room to actually renew. A wait at or past the TTL means the token is already
// dead when the agent wakes up, and the loop then depends on re-auth working —
// which is the fallback path, not the design.
func TestRenewWaitAlwaysLeavesTimeToRenew(t *testing.T) {
	for _, ttl := range []time.Duration{
		6 * time.Second, 30 * time.Second, time.Minute,
		15 * time.Minute, time.Hour, 4 * time.Hour, 24 * time.Hour,
	} {
		w := renewWait(ttl)
		if w >= ttl {
			t.Errorf("renewWait(%v) = %v: the token expires before the agent wakes", ttl, w)
		}
	}
}

// A token that reports no TTL must not turn the loop into a spin. Vault returns
// 0 for a root token, and lookup failures surface the same way, so this is a
// real state rather than a defensive branch.
func TestRenewWaitFloorsAtFiveSecondsForUnknownTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Second, -time.Hour} {
		if got := renewWait(ttl); got != 5*time.Second {
			t.Errorf("renewWait(%v) = %v, want 5s", ttl, got)
		}
	}
}

// Very short TTLs would compute a sub-second wait. The floor keeps the loop
// from spinning; it is deliberately above the two-thirds rule.
func TestRenewWaitFloorBeatsTheTwoThirdsRuleWhenTTLIsTiny(t *testing.T) {
	// 2/3 of 3s is 2s, which is under the floor.
	if got := renewWait(3 * time.Second); got != 5*time.Second {
		t.Errorf("renewWait(3s) = %v, want the 5s floor", got)
	}
}

// A long-lived token must still be renewed periodically rather than after
// hours of silence: a renewal that only happens once a day gives no warning
// before it starts failing.
func TestRenewWaitCapsAtThirtyMinutes(t *testing.T) {
	for _, ttl := range []time.Duration{2 * time.Hour, 24 * time.Hour, 768 * time.Hour} {
		if got := renewWait(ttl); got != 30*time.Minute {
			t.Errorf("renewWait(%v) = %v, want the 30m cap", ttl, got)
		}
	}
}

// Between the floor and the cap the rule is two thirds of what is left, which
// leaves a third of the TTL to recover in if the renewal fails.
func TestRenewWaitUsesTwoThirdsBetweenFloorAndCap(t *testing.T) {
	cases := map[time.Duration]time.Duration{
		30 * time.Second: 20 * time.Second,
		15 * time.Minute: 10 * time.Minute,
		45 * time.Minute: 30 * time.Minute,
	}
	for ttl, want := range cases {
		if got := renewWait(ttl); got != want {
			t.Errorf("renewWait(%v) = %v, want %v", ttl, got, want)
		}
	}
}

// writeSinks is how other tools get the token, so its file mode is a security
// property rather than a detail: a sink readable by the group hands a live
// Vault token to every process on the box.
func TestWriteSinksUses0600AndSkipsEmptyPaths(t *testing.T) {
	dir := t.TempDir()
	v, err := vaultc.New("https://vault.invalid", nil, dir)
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	a := &app.App{Vault: v}

	one := filepath.Join(dir, "sink-a")
	two := filepath.Join(dir, "sink-b")
	m := &Manager{App: a, Sinks: []string{one, "", two}}

	if err := m.writeSinks(); err != nil {
		t.Fatalf("writeSinks: %v", err)
	}
	for _, p := range []string{one, two} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("sink %s: %v", p, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("sink %s perm = %o, want 600", p, got)
		}
	}
	// The empty entry must be skipped, not turned into a path. An unset --sink
	// flag arrives as "", and joining that onto anything yields a real location
	// the token would be written to. Counting the directory is the check that
	// actually distinguishes "skipped" from "written somewhere else".
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(ents) != 2 {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("sink dir holds %v, want exactly the two named sinks", names)
	}
}

// A sink that cannot be written has to surface. Run calls writeSinks before it
// reports success, so swallowing this would announce a working agent whose
// consumers never receive a token.
func TestWriteSinksReportsAnUnwritableSink(t *testing.T) {
	dir := t.TempDir()
	v, err := vaultc.New("https://vault.invalid", nil, dir)
	if err != nil {
		t.Fatalf("vault client: %v", err)
	}
	m := &Manager{App: &app.App{Vault: v}, Sinks: []string{dir}} // a directory
	if err := m.writeSinks(); err == nil {
		t.Fatal("writeSinks accepted a directory as a sink")
	}
}
