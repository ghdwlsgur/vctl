package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// The kv tests follow the source files: this one holds the fake and the
// fixtures every other kv_*_test.go shares, plus what kv.go itself owns.

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

// sampleSecret is one live secret with two string fields, a field that is not
// a string, and operator metadata — every shape a rendering has to handle.
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

// One read for every verb that needs a secret, with the one refinement a
// bare read cannot make: a path that lists is a folder, and saying so beats
// "nothing there" for the operator who typed one segment too few.
func TestFetchKVSecretExplainsWhatItCouldNotRead(t *testing.T) {
	kv := fleetLikeTree()
	kv.secrets = map[string]vaultc.KVSecret{"kv/teams/sre/gitlab-albert": sampleSecret()}
	// The fake denies by exact path; a secret inside the private folder is
	// denied on read the way Vault would deny it.
	kv.denied["kv/teams/private/x"] = true
	ctx := context.Background()

	if sec, err := fetchKVSecret(ctx, kv, "kv/teams/sre/gitlab-albert", 0); err != nil || sec.Path != "kv/teams/sre/example" {
		t.Errorf("read = %+v, %v", sec, err)
	}
	if _, err := fetchKVSecret(ctx, kv, "kv/teams/sre", 0); err == nil || !strings.Contains(err.Error(), "is a folder") {
		t.Errorf("folder = %v, want the folder hint", err)
	}
	if _, err := fetchKVSecret(ctx, kv, "kv/teams/sre/absent", 0); err == nil || !strings.Contains(err.Error(), "nothing at") {
		t.Errorf("missing = %v, want the not-found sentence", err)
	}
	if _, err := fetchKVSecret(ctx, kv, "kv/teams/private/x", 0); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("denied = %v, want the policy sentence", err)
	}
	// A specific version that is missing is a missing version, not a folder;
	// the list that would say so is not made.
	before := len(kv.lists)
	if _, err := fetchKVSecret(ctx, kv, "kv/teams/sre", 2); err == nil || strings.Contains(err.Error(), "is a folder") {
		t.Errorf("versioned miss = %v, want a plain not-found", err)
	}
	if len(kv.lists) != before {
		t.Error("a versioned miss listed the path to look for a folder")
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
		// exec takes the secret and then the command; nothing at all is refused.
		{[]string{"kv", "exec"}, nil, false},
		{[]string{"kv", "exec"}, []string{"gitlab", "sh", "-c", "echo {token}"}, true},
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
