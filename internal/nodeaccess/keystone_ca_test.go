package nodeaccess

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
)

func pemOf(certs ...*x509.Certificate) []byte {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return []byte(b.String())
}

// A farm whose Keystone certificate comes from kolla's own CA (infra-3x5-epoxy:
// CN=InnogridCA) is verifiable once that CA is registered for the farm, and
// only then.
func TestKeystoneRootsTrustTheRegisteredFarmCA(t *testing.T) {
	_, caKey, ca := testCA(t)
	served := testLeaf(t, caKey, ca, x509.ExtKeyUsageServerAuth, nil, nil, []net.IP{net.ParseIP("172.16.0.245")})
	leaf, err := x509.ParseCertificate(served.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	opts := func(p *x509.CertPool) x509.VerifyOptions {
		return x509.VerifyOptions{Roots: p, DNSName: "172.16.0.245"}
	}

	without, err := keystoneRoots(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(opts(without)); err == nil {
		t.Fatal("verified a kolla-issued Keystone certificate with no farm CA registered")
	}
	with, err := keystoneRoots(pemOf(ca))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(opts(with)); err != nil {
		t.Fatalf("registered farm CA did not verify its Keystone certificate: %v", err)
	}
}

// What gets registered is a CA, and nothing else: a leaf pinned as a root
// would keep working after the farm reissued it from a different CA, and a
// private key pasted by mistake must never be stored.
func TestParseKeystoneCAAcceptsOnlyCACertificates(t *testing.T) {
	_, caKey, ca := testCA(t)
	served := testLeaf(t, caKey, ca, x509.ExtKeyUsageServerAuth, nil, nil, []net.IP{net.ParseIP("10.0.0.1")})
	leaf, _ := x509.ParseCertificate(served.Certificate[0])

	if certs, err := ParseKeystoneCA(pemOf(ca)); err != nil || len(certs) != 1 {
		t.Fatalf("a CA certificate was refused: %v", err)
	}
	for name, in := range map[string][]byte{
		"empty":         nil,
		"not pem":       []byte("hello"),
		"leaf":          pemOf(leaf),
		"ca plus leaf":  pemOf(ca, leaf),
		"private key":   append(pemOf(ca), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})...),
		"garbage block": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}),
	} {
		if _, err := ParseKeystoneCA(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
