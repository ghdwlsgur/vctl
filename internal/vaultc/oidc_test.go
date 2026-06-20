package vaultc

import "testing"

func TestOIDCState(t *testing.T) {
	state, err := oidcState("https://vault.example/oidc?client_id=vctl&state=abc123")
	if err != nil {
		t.Fatal(err)
	}
	if state != "abc123" {
		t.Fatalf("state = %q, want abc123", state)
	}
}

func TestOIDCStateRejectsMissingState(t *testing.T) {
	if _, err := oidcState("https://vault.example/oidc?client_id=vctl"); err == nil {
		t.Fatal("oidcState accepted URL without state")
	}
}
