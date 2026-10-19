package nodeaccess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func testIntermediate(t *testing.T, rootKey *ecdsa.PrivateKey, root *x509.Certificate) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "vctl test intermediate"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// Vault issues VM certificates from pki_sre_int, an intermediate under the
// SRE root, and returns it in ca_chain after the leaf. The first DynamicJSON
// guest (2026-10-19) failed enrollment with "certificate signed by unknown
// authority" because the chain check ignored everything after the leaf.
func TestIssuedVMChainVerifiesThroughTheIntermediate(t *testing.T) {
	roots, rootKey, root := testCA(t)
	intKey, intermediate := testIntermediate(t, rootKey, root)
	leaf := testLeaf(t, intKey, intermediate, x509.ExtKeyUsageClientAuth, nil, nil, nil)

	withChain := tls.Certificate{Certificate: [][]byte{leaf.Certificate[0], intermediate.Raw}}
	if err := verifyIssuedVMChain(withChain, roots); err != nil {
		t.Fatalf("a leaf with its intermediate did not verify: %v", err)
	}
	leafOnly := tls.Certificate{Certificate: [][]byte{leaf.Certificate[0]}}
	if err := verifyIssuedVMChain(leafOnly, roots); err == nil {
		t.Fatal("a leaf without its intermediate verified against the root alone")
	}
}

// The chain still has to end at the configured root, and be for client auth.
func TestIssuedVMChainRefusesAForeignRootOrWrongUsage(t *testing.T) {
	roots, rootKey, root := testCA(t)
	_, otherKey, other := testCA(t)
	intKey, intermediate := testIntermediate(t, otherKey, other)
	foreign := testLeaf(t, intKey, intermediate, x509.ExtKeyUsageClientAuth, nil, nil, nil)
	if err := verifyIssuedVMChain(tls.Certificate{Certificate: [][]byte{foreign.Certificate[0], intermediate.Raw}}, roots); err == nil {
		t.Error("verified a chain to a root that is not configured")
	}
	ownInt, ownIntCert := testIntermediate(t, rootKey, root)
	server := testLeaf(t, ownInt, ownIntCert, x509.ExtKeyUsageServerAuth, nil, nil, nil)
	if err := verifyIssuedVMChain(tls.Certificate{Certificate: [][]byte{server.Certificate[0], ownIntCert.Raw}}, roots); err == nil {
		t.Error("verified a server-auth certificate as a VM client identity")
	}
}
