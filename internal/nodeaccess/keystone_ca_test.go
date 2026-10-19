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

// The gateway runs outside every farm, so it often cannot reach the Keystone
// address a farm is registered under: infra-3x5-epoxy is 172.16.0.245:5000 on
// its internal API network, which the sre-core cluster has no route to (the
// first DynamicJSON call timed out there). A registered verify URL — the same
// Keystone's external endpoint — is used instead.
func TestKeystoneTokensURLPrefersTheRegisteredEndpoint(t *testing.T) {
	for _, tc := range []struct{ id, verify, want string }{
		{"172.16.0.245:5000", "", "https://172.16.0.245:5000/v3/auth/tokens"},
		{"172.16.0.245:5000", "https://192.168.201.245:5000", "https://192.168.201.245:5000/v3/auth/tokens"},
		{"172.16.0.245:5000", "https://192.168.201.245:5000/", "https://192.168.201.245:5000/v3/auth/tokens"},
		{"172.16.0.245:5000", "https://192.168.201.245:5000/v3", "https://192.168.201.245:5000/v3/auth/tokens"},
		{"172.16.0.245:5000", "https://keystone.example:5000/identity/v3/", "https://keystone.example:5000/identity/v3/auth/tokens"},
	} {
		got, err := KeystoneTokensURL(tc.id, tc.verify)
		if err != nil || got != tc.want {
			t.Errorf("KeystoneTokensURL(%q, %q) = %q, %v; want %q", tc.id, tc.verify, got, err, tc.want)
		}
	}
}

// A service token with the admin role is about to be sent there, so only an
// operator-registered HTTPS origin is accepted.
func TestKeystoneTokensURLRefusesUnsafeEndpoints(t *testing.T) {
	for _, verify := range []string{
		"http://192.168.201.245:5000",
		"https://user:pw@192.168.201.245:5000",
		"https://192.168.201.245:5000?x=1",
		"https://192.168.201.245:5000#frag",
		"https:///v3",
		"192.168.201.245:5000",
	} {
		if got, err := KeystoneTokensURL("172.16.0.245:5000", verify); err == nil {
			t.Errorf("accepted %q as %q", verify, got)
		}
	}
	if _, err := KeystoneTokensURL("172.16.0.245:5000/evil", ""); err == nil {
		t.Error("accepted a deployment id that is not host:port")
	}
}
