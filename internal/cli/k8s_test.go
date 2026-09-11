package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/kubeconfig"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

type fakeIssuer struct {
	creds   vaultc.K8sCreds
	credErr error
	kv      map[string]map[string]string
	mints   int
}

func (f *fakeIssuer) KubernetesCreds(_ context.Context, mount, role, ns string, _ time.Duration) (vaultc.K8sCreds, error) {
	f.mints++
	if f.credErr != nil {
		return vaultc.K8sCreds{}, f.credErr
	}
	c := f.creds
	c.ServiceAccount = "v-someone-" + role
	c.Namespace = ns
	return c, nil
}

func (f *fakeIssuer) ReadKV(_ context.Context, path string) (map[string]string, error) {
	sec, ok := f.kv[path]
	if !ok {
		return nil, vaultc.ErrKVNotFound
	}
	return sec, nil
}

func TestIssueK8sTokenDispatchesOnTheSource(t *testing.T) {
	iss := &fakeIssuer{creds: vaultc.K8sCreds{Token: "minted-test-token", TTL: time.Hour}, kv: map[string]map[string]string{"kv/teams/x/k8s/edge": {"token": "standin-test-token"}}}
	tok, err := issueK8sToken(context.Background(), iss, "vault:kubernetes/core", "viewer", 0)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Token != "minted-test-token" || tok.ExpiresAt.IsZero() || tok.ServiceAccount != "v-someone-viewer@"+k8sAccessNamespace {
		t.Errorf("vault token = %+v", tok)
	}
	tok, err = issueK8sToken(context.Background(), iss, "kv:kv/teams/x/k8s/edge", "viewer", 0)
	if err != nil || tok.Token != "standin-test-token" || !tok.ExpiresAt.IsZero() {
		t.Errorf("kv token = %+v, %v (a stand-in has no expiry)", tok, err)
	}
	for _, bad := range []string{"file:/x", "kv:kv/teams/x/k8s/missing", "vault"} {
		if _, err := issueK8sToken(context.Background(), iss, bad, "viewer", 0); err == nil {
			t.Errorf("source %q was accepted", bad)
		}
	}
}

func TestExecCredentialJSONShape(t *testing.T) {
	exp := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	raw, err := execCredentialJSON(k8sToken{Token: "t", ExpiresAt: exp})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Status     struct {
			Token string `json:"token"`
			Exp   string `json:"expirationTimestamp"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.APIVersion != "client.authentication.k8s.io/v1" || doc.Kind != "ExecCredential" || doc.Status.Token != "t" || doc.Status.Exp != "2026-09-11T12:00:00Z" {
		t.Errorf("document = %s", raw)
	}
	raw, _ = execCredentialJSON(k8sToken{Token: "t"})
	if strings.Contains(string(raw), "expirationTimestamp") {
		t.Error("a token without expiry must not claim one")
	}
}

func TestK8sTokenCacheHonoursExpiryAndMode(t *testing.T) {
	cache := k8sTokenCache{dir: filepath.Join(t.TempDir(), "k8s")}
	now := time.Now()
	tok := k8sToken{Token: "cached-test-token", ExpiresAt: now.Add(30 * time.Minute)}
	if err := cache.put("core", "viewer", tok); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(cache.path("core", "viewer")); fi.Mode().Perm() != 0o600 {
		t.Errorf("cache file mode = %o", fi.Mode().Perm())
	}
	got, ok, err := cache.get("core", "viewer", now)
	if err != nil || !ok || got.Token != tok.Token {
		t.Fatalf("get = %+v %v %v", got, ok, err)
	}
	// Two minutes before expiry it is already gone.
	if _, ok, _ := cache.get("core", "viewer", tok.ExpiresAt.Add(-time.Minute)); ok {
		t.Error("a token within the slack window was served")
	}
	// Another role is another file.
	if _, ok, _ := cache.get("core", "admin", now); ok {
		t.Error("the viewer token was served for admin")
	}
	// No expiry → never cached.
	if err := cache.put("core", "editor", k8sToken{Token: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := cache.get("core", "editor", now); ok {
		t.Error("an expiry-less token was cached")
	}
	off := k8sTokenCache{dir: cache.dir, disabled: true}
	if _, ok, _ := off.get("core", "viewer", now); ok {
		t.Error("--no-cache still read the cache")
	}
}

func TestK8sKubeconfigEntriesCarryNoCredential(t *testing.T) {
	c := store.K8sCluster{Name: "core", APIServer: "https://198.51.100.10:6443", TLSServerName: "198.51.100.11", CAPEM: "PEM", Reach: "tunnel", TokenSource: "vault:kubernetes/core"}
	cluster, user := k8sKubeconfigEntries(c, "admin", defaultK8sProxy)
	if cluster["server"] != c.APIServer || cluster["tls-server-name"] != "198.51.100.11" || cluster["proxy-url"] != defaultK8sProxy || cluster["certificate-authority-data"] != "UEVN" {
		t.Errorf("cluster entry = %v", cluster)
	}
	ex := user["exec"].(map[string]any)
	args := strings.Join(ex["args"].([]string), " ")
	if ex["command"] != "vctl" || !strings.Contains(args, "--cluster core") || !strings.Contains(args, "--role admin") || !strings.Contains(args, "--source vault:kubernetes/core") {
		t.Errorf("exec = %v", ex)
	}
	for k := range user {
		if k == "token" || k == "client-certificate-data" || k == "client-key-data" {
			t.Errorf("user entry carries a credential field %q", k)
		}
	}
	c.Reach = "direct"
	cluster, _ = k8sKubeconfigEntries(c, "viewer", defaultK8sProxy)
	if _, has := cluster["proxy-url"]; has {
		t.Error("a direct cluster got a proxy-url")
	}
}

func TestK8sImportContextReadsAddressAndCAOnly(t *testing.T) {
	f := &kubeconfig.File{}
	f.SetCluster("c1", map[string]any{"server": "https://198.51.100.10:6443", "certificate-authority-data": "UEVN", "tls-server-name": "api.example.internal"})
	f.SetUser("u1", map[string]any{"token": "not-a-real-token"})
	f.SetContext("ctx1", map[string]any{"cluster": "c1", "user": "u1"})
	imp, err := k8sImportContext([]*kubeconfig.File{f}, "ctx1")
	if err != nil {
		t.Fatal(err)
	}
	if imp.server != "https://198.51.100.10:6443" || imp.caPEM != "PEM" || imp.serverName != "api.example.internal" {
		t.Errorf("import = %+v", imp)
	}
	if _, err := k8sImportContext([]*kubeconfig.File{f}, "nope"); err == nil {
		t.Error("an unknown context was imported")
	}
}

func TestK8sCommandsAreGated(t *testing.T) {
	root := k8sCmd(cmdkit.Env{})
	if root.Annotations["rbac.command"] != "k8s" || root.Annotations["rbac.class"] != string(authz.ClassRead) {
		t.Errorf("root gate = %v", root.Annotations)
	}
	want := map[string]string{"token": "k8s-access", "use": "k8s", "exec": "k8s", "ls": "k8s"}
	for _, sub := range root.Commands() {
		if g, ok := want[sub.Name()]; ok && sub.Annotations["rbac.command"] != g {
			t.Errorf("%s gated as %q, want %q", sub.Name(), sub.Annotations["rbac.command"], g)
		}
		if sub.Name() == "cluster" {
			for _, s2 := range sub.Commands() {
				if s2.Annotations["rbac.command"] != "k8s-inventory" {
					t.Errorf("cluster %s gated as %q", s2.Name(), s2.Annotations["rbac.command"])
				}
			}
		}
	}
}
