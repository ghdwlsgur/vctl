package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Open is the production connection path and the one every other test avoids:
// OpenLocal exists precisely so tests can skip verify-full TLS and Vault-issued
// credentials. That leaves the real path — certificate verification against a
// pinned CA, plus BeforeConnect pulling a fresh credential per physical
// connection — exercised only in production, which is the wrong place to find
// out it is broken.
//
// The CA is a parameter, not a constant, so a throwaway CA verifies the same
// code the embedded SRE CA runs through.
//
// Integration — needs a TLS Postgres and the CA that signed its certificate:
//
//	VCTL_TEST_TLS_HOST      dial host (e.g. 127.0.0.1)
//	VCTL_TEST_TLS_PORT      dial port
//	VCTL_TEST_TLS_SERVER    name to verify the certificate against
//	VCTL_TEST_TLS_CA        path to the CA PEM
//	VCTL_TEST_TLS_USER/PASS static credentials standing in for a Vault lease
func tlsFixture(t *testing.T) (host string, port int, serverName string, caPEM []byte, creds CredsFunc) {
	t.Helper()
	host = os.Getenv("VCTL_TEST_TLS_HOST")
	caPath := os.Getenv("VCTL_TEST_TLS_CA")
	if host == "" || caPath == "" {
		t.Skip("VCTL_TEST_TLS_* not set; skipping TLS integration test")
	}
	port, err := strconv.Atoi(os.Getenv("VCTL_TEST_TLS_PORT"))
	if err != nil {
		t.Fatalf("VCTL_TEST_TLS_PORT: %v", err)
	}
	caPEM, err = os.ReadFile(caPath)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	serverName = os.Getenv("VCTL_TEST_TLS_SERVER")
	user, pass := os.Getenv("VCTL_TEST_TLS_USER"), os.Getenv("VCTL_TEST_TLS_PASS")
	return host, port, serverName, caPEM, func(context.Context) (string, string, error) {
		return user, pass, nil
	}
}

func TestOpenVerifiesTLSAgainstThePinnedCA(t *testing.T) {
	host, port, serverName, caPEM, creds := tlsFixture(t)
	ctx := context.Background()

	st, err := Open(ctx, host, port, "vctl", creds, serverName, caPEM)
	if err != nil {
		t.Fatalf("Open with the correct CA failed: %v", err)
	}
	defer st.Close()

	// Prove the connection actually works, not just that Ping passed.
	if _, err := st.List(ctx, ""); err != nil {
		t.Fatalf("query over the verified connection failed: %v", err)
	}

	// And prove it is encrypted, from the server's point of view. "It connected"
	// is not the property being tested: the bug this guards against connected
	// perfectly well, in cleartext, whenever verification failed.
	var encrypted bool
	if err := st.pool.QueryRow(ctx,
		"SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&encrypted); err != nil {
		t.Fatalf("read pg_stat_ssl: %v", err)
	}
	if !encrypted {
		t.Fatal("the connection carried no TLS — pgx fell back to cleartext")
	}
}

// The pinned CA has to be doing work. An unrelated CA must be rejected — if this
// passes, verify-full has silently degraded to "encrypted but unauthenticated"
// and a man in the middle would go unnoticed.
func TestOpenRejectsAnUntrustedCA(t *testing.T) {
	host, port, serverName, _, creds := tlsFixture(t)

	_, err := Open(context.Background(), host, port, "vctl", creds, serverName, unrelatedCA(t))
	if err == nil {
		t.Fatal("Open accepted a certificate signed by an unrelated CA")
	}
	if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "authority") {
		t.Errorf("error does not look like a verification failure: %v", err)
	}
}

// serverName is what makes a port-forward usable: the dial address is loopback
// while the certificate still has to match its real DNS name. Pointing it at the
// wrong name must fail, or the override would be a way to skip verification.
func TestOpenRejectsAServerNameMismatch(t *testing.T) {
	host, port, _, caPEM, creds := tlsFixture(t)

	_, err := Open(context.Background(), host, port, "vctl", creds, "wrong.example.invalid", caPEM)
	if err == nil {
		t.Fatal("Open accepted a certificate that does not match the requested server name")
	}
}

// BeforeConnect runs per physical connection, which is what lets a long-lived
// pool outlive a short Vault lease. A credential function that fails must
// surface as a connection error rather than a silent fallback to no credentials.
func TestOpenSurfacesCredentialFailures(t *testing.T) {
	host, port, serverName, caPEM, _ := tlsFixture(t)

	failing := func(context.Context) (string, string, error) {
		return "", "", errCreds
	}
	_, err := Open(context.Background(), host, port, "vctl", failing, serverName, caPEM)
	if err == nil {
		t.Fatal("Open succeeded despite the credential fetch failing")
	}
	if !strings.Contains(err.Error(), "fetch db creds") {
		t.Errorf("error does not name the credential failure: %v", err)
	}
}

// unrelatedCA returns a PEM-encoded CA that is structurally valid and signed
// nothing in this fixture. It is generated per run rather than embedded: a
// checked-in certificate eventually expires, and an expired CA fails
// verification too — the test would keep passing for the wrong reason.
func unrelatedCA(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// errCreds stands in for a Vault lookup that failed.
var errCreds = errorString("vault unavailable")

type errorString string

func (e errorString) Error() string { return string(e) }
