package vaultc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A missing token file means "not in a pod", which is the ordinary case on a
// workstation. Reporting it as an error would make every laptop run fail on an
// auth method it was never going to use.
func TestReadServiceAccountTokenTreatsAbsenceAsNotAPod(t *testing.T) {
	tok, found, err := ReadServiceAccountToken(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("a missing token file was reported as an error: %v", err)
	}
	if found || tok != "" {
		t.Errorf("ReadServiceAccountToken = %q, %v; want empty and not found", tok, found)
	}
}

// An empty file is different: something mounted a token and it has no contents.
// Falling through silently would send the caller to a method that prompts.
func TestReadServiceAccountTokenRejectsAnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadServiceAccountToken(path); err == nil {
		t.Error("an empty token file was accepted")
	}
}

// Projected tokens arrive with a trailing newline often enough that not
// trimming it is a real failure mode — Vault rejects the JWT and the message
// says nothing about whitespace.
func TestReadServiceAccountTokenTrimsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("  header.payload.sig\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, found, err := ReadServiceAccountToken(path)
	if err != nil || !found {
		t.Fatalf("ReadServiceAccountToken: %v, found=%v", err, found)
	}
	if tok != "header.payload.sig" {
		t.Errorf("token = %q, want it trimmed", tok)
	}
}

// The default path is the one the kubelet projects into every pod, so a caller
// that configures nothing still works inside the cluster.
func TestReadServiceAccountTokenDefaultsToTheProjectedPath(t *testing.T) {
	if !strings.HasPrefix(DefaultServiceAccountTokenPath, "/var/run/secrets/kubernetes.io/") {
		t.Errorf("default path %q is not where the kubelet projects the token", DefaultServiceAccountTokenPath)
	}
	// Passing "" must fall back to it rather than reading the current directory.
	_, found, err := ReadServiceAccountToken("")
	if err != nil {
		t.Fatalf("empty path: %v", err)
	}
	_, statErr := os.Stat(DefaultServiceAccountTokenPath)
	if found != (statErr == nil) {
		t.Errorf("found=%v does not match whether the default path exists", found)
	}
}

// The role is what Vault binds to a ServiceAccount, so there is no useful
// request without it. Failing before the round trip says which input is
// missing; Vault's own error would say the path is invalid.
func TestLoginKubernetesRequiresRoleAndToken(t *testing.T) {
	c := &Client{}
	if err := c.LoginKubernetes(t.Context(), "kubernetes", "", "jwt"); err == nil {
		t.Error("login with no role was attempted")
	} else if !strings.Contains(err.Error(), "role") {
		t.Errorf("error %q does not name the missing input", err)
	}
	if err := c.LoginKubernetes(t.Context(), "kubernetes", "vctl-migrate", "  "); err == nil {
		t.Error("login with a blank token was attempted")
	} else if !strings.Contains(err.Error(), "token") {
		t.Errorf("error %q does not name the missing input", err)
	}
}
