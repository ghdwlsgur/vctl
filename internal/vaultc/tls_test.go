package vaultc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// testCAPEM is a throwaway self-signed CA, enough for ConfigureTLS to build a
// root pool from. Nothing connects to anything in these tests.
func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vctl test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func transportOf(t *testing.T, c *Client) *http.Transport {
	t.Helper()
	tr, ok := c.api.CloneConfig().HttpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", c.api.CloneConfig().HttpClient.Transport)
	}
	return tr
}

// The embedded CA is the trust anchor for everything vctl does with Vault. A
// leftover VAULT_SKIP_VERIFY in the operator's shell used to switch verification
// off without a word — the library reads it before our ConfigureTLS runs and
// ConfigureTLS never sets the flag back.
func TestNewIgnoresVaultSkipVerifyFromTheEnvironment(t *testing.T) {
	t.Setenv("VAULT_SKIP_VERIFY", "true")

	c, err := New("https://vault.example.invalid:8200", testCAPEM(t), t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr := transportOf(t, c)
	if tr.TLSClientConfig == nil {
		t.Fatal("no TLS config was installed at all")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("VAULT_SKIP_VERIFY disabled certificate verification")
	}
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("the embedded CA was not installed as the root pool")
	}
}

// Same anchor, other direction: the address comes from vctl's config, not from
// a VAULT_AGENT_ADDR that would route every request through another process.
func TestNewIgnoresVaultAgentAddrFromTheEnvironment(t *testing.T) {
	t.Setenv("VAULT_AGENT_ADDR", "http://127.0.0.1:1")
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:2")

	const want = "https://vault.example.invalid:8200"
	c, err := New(want, testCAPEM(t), t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.api.Address(); got != want {
		t.Fatalf("client address = %q, want %q", got, want)
	}
}

// Without an embedded CA there is nothing to pin, but the environment still
// must not turn verification off.
func TestNewWithoutCAStillVerifies(t *testing.T) {
	t.Setenv("VAULT_SKIP_VERIFY", "1")

	c, err := New("https://vault.example.invalid:8200", nil, t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr := transportOf(t, c)
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("VAULT_SKIP_VERIFY disabled certificate verification")
	}
}
