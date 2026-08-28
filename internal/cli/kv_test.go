package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// fakeKV is a KV tree in memory: folders map to their entries, secrets to
// their contents, and some folders answer 403 or fail outright. Safe under
// concurrent use because walkKV lists a level in parallel and the race
// detector runs over these tests.
type fakeKV struct {
	tree    map[string][]string
	secrets map[string]vaultc.KVSecret
	denied  map[string]bool
	broken  map[string]bool

	mu    sync.Mutex
	lists []string
}

func (f *fakeKV) ListKV(_ context.Context, path string) ([]string, error) {
	f.mu.Lock()
	f.lists = append(f.lists, path)
	f.mu.Unlock()
	switch {
	case f.denied[path]:
		return nil, fmt.Errorf("%s: %w", path, &vault.ResponseError{StatusCode: http.StatusForbidden})
	case f.broken[path]:
		return nil, errors.New("dial tcp: connection refused")
	}
	keys, ok := f.tree[path]
	if !ok {
		return nil, fmt.Errorf("%s: %w", path, vaultc.ErrKVNotFound)
	}
	return keys, nil
}

func (f *fakeKV) ReadKVSecret(_ context.Context, path string, _ int) (vaultc.KVSecret, error) {
	if f.denied[path] {
		return vaultc.KVSecret{}, fmt.Errorf("%s: %w", path, &vault.ResponseError{StatusCode: http.StatusForbidden})
	}
	sec, ok := f.secrets[path]
	if !ok {
		return vaultc.KVSecret{}, fmt.Errorf("%s: %w", path, vaultc.ErrKVNotFound)
	}
	return sec, nil
}

// fleetLikeTree mirrors the shapes the real mount has: a team folder beside a
// private one, and a name used by a secret and a folder at once.
func fleetLikeTree() *fakeKV {
	return &fakeKV{
		tree: map[string][]string{
			"kv":                     {"backups/", "teams/"},
			"kv/backups":             {"nightly"},
			"kv/teams":               {"private/", "sre/"},
			"kv/teams/sre":           {"backstage", "backstage/", "gitlab-albert", "gitlab-mirror-deploy-tokens/"},
			"kv/teams/sre/backstage": {"oidc"},
			"kv/teams/sre/gitlab-mirror-deploy-tokens": {"repo-a", "repo-b"},
		},
		denied: map[string]bool{"kv/teams/private": true},
	}
}

func TestKVRootIsTheFarmPrefixMount(t *testing.T) {
	for _, tc := range []struct {
		prefix, want string
	}{
		{"kv/teams/sre", "kv"},
		{"/secret/teams/x/", "secret"},
		{"", "kv"},
	} {
		if got := kvRoot(&config.Config{VaultFarmPrefix: tc.prefix}); got != tc.want {
			t.Errorf("kvRoot(%q) = %q, want %q", tc.prefix, got, tc.want)
		}
	}
	if got := kvRoot(nil); got != "kv" {
		t.Errorf("kvRoot(nil) = %q, want kv", got)
	}
}

func TestNormalizeKVPathCleansWhatWasTyped(t *testing.T) {
	for in, want := range map[string]string{
		"kv/teams/sre":      "kv/teams/sre",
		"/kv/teams/sre/":    "kv/teams/sre",
		" kv//teams///sre ": "kv/teams/sre",
		"/":                 "",
		"":                  "",
	} {
		if got := normalizeKVPath(in); got != want {
			t.Errorf("normalizeKVPath(%q) = %q, want %q", in, got, want)
		}
	}
}

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

func sampleSecret() vaultc.KVSecret {
	return vaultc.KVSecret{
		Path:           "kv/teams/sre/example",
		Data:           map[string]string{"token": "token-field-value", "username": "someone"},
		NonString:      []string{"retries"},
		Version:        3,
		CreatedAt:      time.Date(2026, 6, 19, 0, 0, 0, 0, time.UTC),
		CustomMetadata: map[string]string{"owner": "sre"},
	}
}

// The default never puts a value on the screen. The keys are there — that is
// what "is the field there" needs — and so is the way to see more.
func TestRenderKVSecretMasksValuesByDefault(t *testing.T) {
	var out bytes.Buffer
	renderKVSecret(&out, sampleSecret(), false)
	text := ui.StripANSI(out.String())
	for _, want := range []string{"kv/teams/sre/example", "v3", "token", "username", "retries", kvMask, "--reveal", "owner=sre"} {
		if !strings.Contains(text, want) {
			t.Errorf("masked output missing %q:\n%s", want, text)
		}
	}
	for _, leak := range []string{"token-field-value", "someone"} {
		if strings.Contains(text, leak) {
			t.Errorf("masked output shows the value %q:\n%s", leak, text)
		}
	}
}

func TestRenderKVSecretRevealsOnRequest(t *testing.T) {
	var out bytes.Buffer
	renderKVSecret(&out, sampleSecret(), true)
	text := ui.StripANSI(out.String())
	for _, want := range []string{"token-field-value", "someone"} {
		if !strings.Contains(text, want) {
			t.Errorf("revealed output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, kvMask) || strings.Contains(text, "--reveal") {
		t.Errorf("revealed output still masks or hints:\n%s", text)
	}
}

// An empty field list would read as a secret with no fields. A deleted version
// has fields; they are hidden, and the output has to say so.
func TestRenderKVSecretSaysWhenAVersionIsDeleted(t *testing.T) {
	sec := sampleSecret()
	sec.Data = nil
	sec.DeletedAt = time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	renderKVSecret(&out, sec, true)
	if text := ui.StripANSI(out.String()); !strings.Contains(text, "deleted") {
		t.Errorf("deleted version rendered without saying so:\n%s", text)
	}
}

// Structured output follows the same rule as the table: data only on request,
// and then absent rather than masked — a placeholder string is a value to a
// program.
func TestKVGetOutputCarriesDataOnlyWhenRevealed(t *testing.T) {
	sec := sampleSecret()
	hidden, err := json.Marshal(newKVGetOutput(sec, false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hidden), `"data"`) || strings.Contains(string(hidden), "token-field-value") {
		t.Errorf("hidden output carries data: %s", hidden)
	}
	if !strings.Contains(string(hidden), `"keys":["token","username"]`) {
		t.Errorf("hidden output lacks the key list: %s", hidden)
	}
	revealed, err := json.Marshal(newKVGetOutput(sec, true))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(revealed), `"token":"token-field-value"`) {
		t.Errorf("revealed output lacks the data: %s", revealed)
	}
}

func TestKVErrorSeparatesMissingFromForbidden(t *testing.T) {
	missing := kvError(fmt.Errorf("x: %w", vaultc.ErrKVNotFound), "kv/x")
	if !strings.Contains(missing.Error(), "nothing at kv/x") || !strings.Contains(missing.Error(), "kv search") {
		t.Errorf("missing = %v", missing)
	}
	forbidden := kvError(&vault.ResponseError{StatusCode: http.StatusForbidden}, "kv/x")
	if !strings.Contains(forbidden.Error(), "permission denied") || !strings.Contains(forbidden.Error(), "whoami") {
		t.Errorf("forbidden = %v", forbidden)
	}
	other := errors.New("dial tcp: connection refused")
	if kvError(other, "kv/x") != other {
		t.Error("an unrelated error was rewritten")
	}
}

// Wiring: every kv subcommand is gated as a read of "kv", offers structured
// output, and sits with the other access commands.
func TestKVCommandsAreWiredAsReadsWithStructuredOutput(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	kv := findCmd(root, "kv")
	if kv == nil {
		t.Fatal("kv command missing from the tree")
	}
	if kv.GroupID != "access" {
		t.Errorf("kv is in group %q, want access", kv.GroupID)
	}
	// The bare command reads too, so it carries the same gate and output contract.
	if kv.Annotations["rbac.command"] != "kv" || kv.Annotations["rbac.class"] != string(classRead) || kv.Annotations[structuredOutputAnnotation] != "true" {
		t.Errorf("bare kv annotations = %v, want a read gate with structured output", kv.Annotations)
	}
	for _, name := range []string{"list", "get", "search"} {
		sub := findCmd(kv, name)
		if sub == nil {
			t.Errorf("kv %s missing", name)
			continue
		}
		if sub.Annotations["rbac.command"] != "kv" || sub.Annotations["rbac.class"] != string(classRead) {
			t.Errorf("kv %s annotations = %v, want a read gate named kv", name, sub.Annotations)
		}
		if sub.Annotations[structuredOutputAnnotation] != "true" {
			t.Errorf("kv %s does not offer -o json", name)
		}
	}
}

// The argument shapes that would run something other than what was typed are
// refused before anything opens.
func TestKVArgumentContracts(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	for _, tc := range []struct {
		path []string
		args []string
		ok   bool
	}{
		// The bare command and get take a word, a path, or nothing (the picker).
		{[]string{"kv"}, nil, true},
		{[]string{"kv"}, []string{"gitlab"}, true},
		{[]string{"kv"}, []string{"a", "b"}, false},
		{[]string{"kv", "list"}, nil, true},
		{[]string{"kv", "list"}, []string{"kv/teams"}, true},
		{[]string{"kv", "list"}, []string{"a", "b"}, false},
		{[]string{"kv", "get"}, nil, true},
		{[]string{"kv", "get"}, []string{"kv/teams/x"}, true},
		{[]string{"kv", "get"}, []string{"a", "b"}, false},
		{[]string{"kv", "search"}, nil, false},
		{[]string{"kv", "search"}, []string{"gitlab", "token"}, true},
	} {
		cmd, _, err := root.Find(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := cmd.Args(cmd, tc.args) == nil; got != tc.ok {
			t.Errorf("%s %v accepted=%v, want %v", strings.Join(tc.path, " "), tc.args, got, tc.ok)
		}
	}
}

// --field prints one value; --reveal shows them all. Both at once is a question
// the command cannot answer.
func TestKVGetRefusesFieldWithReveal(t *testing.T) {
	root := NewRoot(fakeDeps(t))
	get, _, err := root.Find([]string{"kv", "get"})
	if err != nil {
		t.Fatal(err)
	}
	f := get.Flags().Lookup("field")
	if f == nil {
		t.Fatal("no --field")
	}
	if groups := mutuallyExclusiveWith(f); !strings.Contains(strings.Join(groups, " "), "reveal") {
		t.Errorf("--field is not exclusive with --reveal: %v", groups)
	}
}

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
