package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/config"
)

// Outside a cluster there is no token file, so kubernetes auth has to decline
// rather than fail. EnsureLogin tries it before falling back, and an error here
// would break every workstation run of every command.
func TestTryKubernetesLoginDeclinesOutsideAPod(t *testing.T) {
	a := &App{Cfg: &config.Config{
		KubernetesRole:      "vctl-migrate",
		KubernetesTokenFile: filepath.Join(t.TempDir(), "absent"),
	}}
	ok, err := a.tryKubernetesLogin(t.Context())
	if err != nil {
		t.Fatalf("a missing token file failed instead of declining: %v", err)
	}
	if ok {
		t.Error("kubernetes auth claimed the attempt with no token available")
	}
}

// No role configured means the operator never asked for this method. Declining
// keeps it out of the way on every host that will never use it.
func TestTryKubernetesLoginDeclinesWithoutARole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("header.payload.sig"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: &config.Config{KubernetesTokenFile: path}}
	ok, err := a.tryKubernetesLogin(t.Context())
	if err != nil || ok {
		t.Errorf("tryKubernetesLogin = %v, %v; want declined", ok, err)
	}
}

// Configured for kubernetes auth but the token cannot be read: that is a real
// failure, not an absence. Falling through would send an unattended pod to a
// method that waits for a password.
func TestTryKubernetesLoginReportsAnUnreadableToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &App{Cfg: &config.Config{KubernetesRole: "vctl-migrate", KubernetesTokenFile: path}}
	ok, err := a.tryKubernetesLogin(t.Context())
	if err == nil {
		t.Fatal("an empty token file was treated as absence")
	}
	if !ok {
		t.Error("the attempt was not claimed, so the caller would fall through to a prompt")
	}
}

// An unknown method still has to be rejected by name. Adding a case must not
// turn the default branch into a silent accept.
func TestLoginRejectsAnUnknownMethod(t *testing.T) {
	a := &App{Cfg: &config.Config{}}
	err := a.Login(t.Context(), "saml")
	if err == nil {
		t.Fatal("Login accepted an unknown method")
	}
	if !strings.Contains(err.Error(), "saml") {
		t.Errorf("error %q does not name the method", err)
	}
}

// Asking for kubernetes auth explicitly, outside a pod, has to say why it
// cannot — not decline silently the way the automatic attempt does.
func TestLoginKubernetesOutsideAPodExplainsItself(t *testing.T) {
	a := &App{Cfg: &config.Config{
		KubernetesRole:      "vctl-migrate",
		KubernetesTokenFile: filepath.Join(t.TempDir(), "absent"),
	}}
	err := a.Login(t.Context(), "kubernetes")
	if err == nil {
		t.Fatal("an explicit kubernetes login succeeded with no token")
	}
	if !strings.Contains(err.Error(), "pod") {
		t.Errorf("error %q does not explain the condition", err)
	}
}
