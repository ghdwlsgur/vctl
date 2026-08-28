package cli

import (
	"context"
	"strings"
	"testing"
)

// gitlabTree has the shape that makes a word ambiguous on the real mount: a
// secret named exactly "gitlab", siblings that contain the word, and a backup
// copy of one of them under another folder.
func gitlabTree() *fakeKV {
	return &fakeKV{
		tree: map[string][]string{
			"kv":              {"backups/", "teams/"},
			"kv/backups":      {"copy/"},
			"kv/backups/copy": {"gitlab-albert"},
			"kv/teams":        {"sre/"},
			"kv/teams/sre":    {"gitlab", "gitlab-albert", "gitlab-mirror", "netbox"},
		},
	}
}

// A full path is the answer itself: nothing is listed, so a script that names
// its secret pays one read and no walk.
func TestResolveKVPathTakesAFullPathWithoutWalking(t *testing.T) {
	kv := gitlabTree()
	got, err := resolveKVPath(context.Background(), kv, "kv", []string{"/kv/teams/sre/gitlab-albert/"})
	if err != nil || got != "kv/teams/sre/gitlab-albert" {
		t.Fatalf("resolve = %q, %v", got, err)
	}
	if len(kv.lists) != 0 {
		t.Errorf("a full path listed %v; it should not have walked", kv.lists)
	}
}

// One match is an answer. Tests run without a terminal, so this is also the
// proof that an unambiguous word needs no picker.
func TestResolveKVPathReadsTheOneSecretAWordMatches(t *testing.T) {
	got, err := resolveKVPath(context.Background(), gitlabTree(), "kv", []string{"netbox"})
	if err != nil || got != "kv/teams/sre/netbox" {
		t.Fatalf("resolve = %q, %v", got, err)
	}
}

// "gitlab" is inside four paths and is the whole name of one. The exact name
// wins — inv.Resolve's rule for hostnames — so typing a secret's name reads
// that secret rather than opening a picker over everything that mentions it.
func TestResolveKVPathPrefersTheExactName(t *testing.T) {
	got, err := resolveKVPath(context.Background(), gitlabTree(), "kv", []string{"GitLab"})
	if err != nil || got != "kv/teams/sre/gitlab" {
		t.Fatalf("resolve = %q, %v", got, err)
	}
}

// Two secrets are named gitlab-albert — the real one and a backup copy. Without
// a terminal that is an error naming both, never the one that sorted first.
func TestResolveKVPathRefusesToGuessWithoutATerminal(t *testing.T) {
	_, err := resolveKVPath(context.Background(), gitlabTree(), "kv", []string{"gitlab-albert"})
	if err == nil {
		t.Fatal("an ambiguous word resolved without a terminal")
	}
	for _, want := range []string{"2 secrets", "kv/backups/copy/gitlab-albert", "kv/teams/sre/gitlab-albert"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if _, err := resolveKVPath(context.Background(), gitlabTree(), "kv", nil); err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Errorf("no argument and no terminal = %v, want a refusal", err)
	}
}

func TestResolveKVPathReportsNoMatch(t *testing.T) {
	_, err := resolveKVPath(context.Background(), gitlabTree(), "kv", []string{"harbor"})
	if err == nil || !strings.Contains(err.Error(), `no secret matches "harbor"`) {
		t.Fatalf("err = %v", err)
	}
}

// Tabs are the folder two below the mount — a team — or one below when the
// tree is shallower there.
func TestKVPickGroupIsTheFolderTwoBelowTheMount(t *testing.T) {
	for path, want := range map[string]string{
		"kv/teams/sre/gitlab":                    "teams/sre",
		"kv/teams/sre/gitlab-mirror-tokens/repo": "teams/sre",
		"kv/backups/nightly":                     "backups",
		"kv/loose":                               "",
	} {
		if got := kvPickGroup(path, "kv"); got != want {
			t.Errorf("kvPickGroup(%q) = %q, want %q", path, got, want)
		}
	}
}
