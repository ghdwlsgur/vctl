package kubeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = `apiVersion: v1
kind: Config
preferences: {}
some-tool-extension:
  keep: me
clusters:
- name: other
  cluster:
    server: https://198.51.100.5:6443
    certificate-authority-data: QUJD
    insecure-skip-tls-verify: false
- name: vctl-core
  cluster:
    server: https://old.example.internal:6443
contexts:
- name: other
  context:
    cluster: other
    user: other-user
    namespace: kube-system
users:
- name: other-user
  user:
    token: not-a-real-token
current-context: other
`

func TestEditKeepsWhatItDoesNotOwn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f.SetCluster("vctl-core", map[string]any{"server": "https://198.51.100.10:6443", "proxy-url": "socks5://127.0.0.1:1080"})
	f.SetUser("vctl-core-viewer", map[string]any{"exec": map[string]any{"command": "vctl", "args": []string{"k8s", "token", "--cluster", "core"}}})
	f.SetContext("core", map[string]any{"cluster": "vctl-core", "user": "vctl-core-viewer"})
	f.Use("core")
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", fi.Mode().Perm())
	}

	g, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// Ours: replaced, not duplicated.
	c, ok := g.Cluster("vctl-core")
	if !ok || c["server"] != "https://198.51.100.10:6443" || c["proxy-url"] != "socks5://127.0.0.1:1080" {
		t.Errorf("vctl-core = %v", c)
	}
	if n := len(g.Clusters); n != 2 {
		t.Errorf("clusters = %d, want 2 (other + vctl-core)", n)
	}
	// Theirs: untouched, including fields we never model.
	other, _ := g.Cluster("other")
	if other["certificate-authority-data"] != "QUJD" || other["insecure-skip-tls-verify"] != false {
		t.Errorf("other cluster changed: %v", other)
	}
	if ctx, _ := g.Context("other"); ctx["namespace"] != "kube-system" {
		t.Errorf("other context changed: %v", ctx)
	}
	if g.Extra["some-tool-extension"] == nil {
		t.Error("an unknown top-level key was dropped")
	}
	if g.CurrentContext != "core" {
		t.Errorf("current-context = %q", g.CurrentContext)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "not-a-real-token") {
		t.Error("another user's credential was lost on save")
	}
}

func TestLoadMissingFileIsAnEmptyConfig(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "none", "config"))
	if err != nil {
		t.Fatal(err)
	}
	if f.APIVersion != "v1" || f.Kind != "Config" || len(f.Clusters) != 0 {
		t.Errorf("empty config = %+v", f)
	}
	path := filepath.Join(t.TempDir(), ".kube", "config")
	f.SetContext("x", map[string]any{"cluster": "x", "user": "x"})
	if err := f.Save(path); err != nil {
		t.Fatalf("save into a missing directory: %v", err)
	}
}

func TestDefaultPathHonoursKUBECONFIGFirstEntry(t *testing.T) {
	t.Setenv("KUBECONFIG", "/tmp/a"+string(os.PathListSeparator)+"/tmp/b")
	if p, _ := DefaultPath(); p != "/tmp/a" {
		t.Errorf("DefaultPath = %q", p)
	}
	t.Setenv("KUBECONFIG", "")
	if p, _ := DefaultPath(); !strings.HasSuffix(p, filepath.Join(".kube", "config")) {
		t.Errorf("DefaultPath = %q", p)
	}
}
