package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// The contract search is built on: a folder the token may not list is
// reported, and everything else is still found — including the secret and the
// folder that share the name "backstage".
func TestWalkKVSkipsDeniedFoldersAndKeepsGoing(t *testing.T) {
	kv := fleetLikeTree()
	walk, err := walkKV(context.Background(), kv, "kv", 1000)
	if err != nil {
		t.Fatalf("walkKV: %v", err)
	}
	wantSecrets := []string{
		"kv/backups/nightly",
		"kv/teams/sre/backstage",
		"kv/teams/sre/backstage/oidc",
		"kv/teams/sre/gitlab-albert",
		"kv/teams/sre/gitlab-mirror-deploy-tokens/repo-a",
		"kv/teams/sre/gitlab-mirror-deploy-tokens/repo-b",
	}
	if fmt.Sprint(walk.Secrets) != fmt.Sprint(wantSecrets) {
		t.Errorf("Secrets = %v\nwant      %v", walk.Secrets, wantSecrets)
	}
	if fmt.Sprint(walk.Denied) != "[kv/teams/private]" {
		t.Errorf("Denied = %v, want the private folder", walk.Denied)
	}
	if walk.Folders != 6 || walk.Capped {
		t.Errorf("Folders = %d, Capped = %v; want 6 answered and no cap", walk.Folders, walk.Capped)
	}
}

func TestWalkKVStopsAtTheLimit(t *testing.T) {
	walk, err := walkKV(context.Background(), fleetLikeTree(), "kv", 3)
	if err != nil {
		t.Fatalf("walkKV: %v", err)
	}
	if !walk.Capped {
		t.Fatal("a tree larger than the limit did not report Capped")
	}
	if len(walk.Secrets) > 3 {
		t.Errorf("%d secrets past a limit of 3", len(walk.Secrets))
	}
}

// A root that is not there is the answer, not an empty result: "no matches"
// for a mistyped --under would send someone looking for a secret that was
// never searched for.
func TestWalkKVReportsAMissingRoot(t *testing.T) {
	_, err := walkKV(context.Background(), fleetLikeTree(), "kv/nowhere", 100)
	if !errors.Is(err, vaultc.ErrKVNotFound) {
		t.Fatalf("err = %v, want ErrKVNotFound", err)
	}
}

// A transport failure is not a 403 and not a 404. Skipping it would report the
// paths behind it as absent.
func TestWalkKVAbortsOnATransportFailure(t *testing.T) {
	kv := fleetLikeTree()
	kv.broken = map[string]bool{"kv/teams/sre": true}
	_, err := walkKV(context.Background(), kv, "kv", 100)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v, want the transport failure surfaced", err)
	}
}

// A folder that vanished between its parent's listing and ours is not worth
// aborting for; below the root a 404 is skipped.
func TestWalkKVIgnoresAFolderThatVanished(t *testing.T) {
	kv := fleetLikeTree()
	delete(kv.tree, "kv/backups")
	walk, err := walkKV(context.Background(), kv, "kv", 100)
	if err != nil {
		t.Fatalf("walkKV: %v", err)
	}
	for _, s := range walk.Secrets {
		if strings.HasPrefix(s, "kv/backups/") {
			t.Errorf("a vanished folder still contributed %s", s)
		}
	}
}

func TestMatchesAllFoldNeedsEveryTerm(t *testing.T) {
	p := "kv/teams/sre/GitLab-albert"
	for _, tc := range []struct {
		terms []string
		want  bool
	}{
		{[]string{"gitlab"}, true},
		{[]string{"GITLAB", "albert"}, true},
		{[]string{"gitlab", "token"}, false},
		{[]string{"sre/gitlab"}, true},
		{nil, true},
	} {
		if got := matchesAllFold(p, tc.terms); got != tc.want {
			t.Errorf("matchesAllFold(%q, %v) = %v, want %v", p, tc.terms, got, tc.want)
		}
	}
}

func TestHighlightFoldKeepsTheTextIntact(t *testing.T) {
	for _, s := range []string{"kv/teams/sre/gitlab-albert", "kv/teams/sre/GitLab/gitlab", "plain"} {
		if got := ui.StripANSI(highlightFold(s, []string{"gitlab", "sre"})); got != s {
			t.Errorf("highlightFold changed the text: %q -> %q", s, got)
		}
	}
}
