package cli

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

func TestKVSetMergesUnderCheckAndSet(t *testing.T) {
	kv := &fakeKV{secrets: map[string]vaultc.KVSecret{
		"kv/teams/x/app": {Path: "kv/teams/x/app", Version: 4, Data: map[string]string{"user": "svc", "old": "gone-soon", "keep": "yes"}},
	}}
	res, err := kvSet(context.Background(), kv, "kv/teams/x/app", map[string]string{"user": "svc2", "url": "https://example.internal"}, []string{"old", "absent"}, false)
	if err != nil {
		t.Fatal(err)
	}
	w := kv.writes[0]
	if w.cas != 4 {
		t.Errorf("cas = %d, want the version that was read (4)", w.cas)
	}
	want := map[string]string{"user": "svc2", "url": "https://example.internal", "keep": "yes"}
	if len(w.data) != len(want) {
		t.Fatalf("wrote %v, want %v", w.data, want)
	}
	for k, v := range want {
		if w.data[k] != v {
			t.Errorf("%s = %q, want %q", k, w.data[k], v)
		}
	}
	if res.Version != 5 || res.Created || strings.Join(res.Set, ",") != "url,user" || strings.Join(res.Removed, ",") != "old" || res.Kept != 1 {
		t.Errorf("result = %+v", res)
	}
	// A removal of a field that is not there is not an event.
	if strings.Contains(strings.Join(res.Removed, ","), "absent") {
		t.Error("reported removing a field that did not exist")
	}
}

func TestKVSetCreatesWithCASZero(t *testing.T) {
	kv := &fakeKV{}
	res, err := kvSet(context.Background(), kv, "kv/teams/x/new", map[string]string{"a": "1"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if kv.writes[0].cas != 0 || !res.Created || res.Version != 1 {
		t.Errorf("create: cas=%d res=%+v", kv.writes[0].cas, res)
	}
}

// Another writer lands between the read and the write. The first write is
// refused; the retry must reapply onto what they wrote, not over it.
func TestKVSetRetriesOntoTheConcurrentWrite(t *testing.T) {
	kv := &fakeKV{secrets: map[string]vaultc.KVSecret{
		"kv/teams/x/app": {Path: "kv/teams/x/app", Version: 1, Data: map[string]string{"a": "1"}},
	}}
	kv.conflictOnce = true
	// Simulate their write by bumping the stored secret before our retry reads it.
	kv.secrets["kv/teams/x/app"] = vaultc.KVSecret{Path: "kv/teams/x/app", Version: 2, Data: map[string]string{"a": "1", "theirs": "kept"}}
	res, err := kvSet(context.Background(), kv, "kv/teams/x/app", map[string]string{"mine": "x"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	final := kv.secrets["kv/teams/x/app"].Data
	if final["theirs"] != "kept" || final["mine"] != "x" || final["a"] != "1" {
		t.Errorf("the retry lost a field: %v", final)
	}
	if res.Version != 3 {
		t.Errorf("version = %d, want 3", res.Version)
	}
}

func TestKVSetReplaceWritesExactlyTheGivenFields(t *testing.T) {
	kv := &fakeKV{secrets: map[string]vaultc.KVSecret{
		"kv/teams/x/app": {Path: "kv/teams/x/app", Version: 7, Data: map[string]string{"a": "1", "b": "2"}},
	}}
	if _, err := kvSet(context.Background(), kv, "kv/teams/x/app", map[string]string{"c": "3"}, nil, true); err != nil {
		t.Fatal(err)
	}
	w := kv.writes[0]
	if w.cas != -1 || len(w.data) != 1 || w.data["c"] != "3" {
		t.Errorf("replace wrote %v with cas %d", w.data, w.cas)
	}
}

func TestKVSetRefusesToEmptyASecret(t *testing.T) {
	kv := &fakeKV{secrets: map[string]vaultc.KVSecret{
		"kv/teams/x/app": {Path: "kv/teams/x/app", Version: 1, Data: map[string]string{"only": "1"}},
	}}
	if _, err := kvSet(context.Background(), kv, "kv/teams/x/app", nil, []string{"only"}, false); err == nil || !strings.Contains(err.Error(), "no fields") {
		t.Errorf("emptying was allowed: %v", err)
	}
	if len(kv.writes) != 0 {
		t.Error("an empty secret was written")
	}
}

func TestParseKVAssignmentsSources(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/ca.pem"
	if err := writeTestFile(file, "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n"); err != nil {
		t.Fatal(err)
	}
	sets, literal, err := parseKVAssignments([]string{"user=svc", "ca=@" + file, "token=-", `at=\@literal`}, strings.NewReader("tok-value\n"))
	if err != nil {
		t.Fatal(err)
	}
	if sets["user"] != "svc" || !strings.HasPrefix(sets["ca"], "-----BEGIN") || sets["token"] != "tok-value" || sets["at"] != "@literal" {
		t.Errorf("parsed %v", sets)
	}
	if !literal {
		t.Error("a command-line value was not reported as literal")
	}
	if _, literal, _ := parseKVAssignments([]string{"ca=@" + file}, nil); literal {
		t.Error("a file value was reported as literal")
	}
	for _, bad := range [][]string{{"novalue"}, {"=x"}, {"bad key=x"}, {"a=1", "a=2"}, {"a=-", "b=-"}} {
		if _, _, err := parseKVAssignments(bad, strings.NewReader("")); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

func TestKVSetIsGatedAsMutate(t *testing.T) {
	cmd := kvSetCmd(cmdkit.Env{})
	if cmd.Annotations["rbac.command"] != "kv-set" || cmd.Annotations["rbac.class"] != string(authz.ClassMutate) {
		t.Errorf("annotations = %v", cmd.Annotations)
	}
}

func writeTestFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }
