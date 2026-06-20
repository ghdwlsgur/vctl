package sshc

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCertSignerRequestsOnlyRequestedExtensions(t *testing.T) {
	tests := []struct {
		name       string
		extensions []string
	}{
		{name: "interactive target", extensions: ptyExtensions},
		{name: "jump hop", extensions: portForwardExtensions},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotExtensions []string
			sign := func(role, publicKey string, principals []string, extensions []string) (string, error) {
				gotExtensions = append([]string(nil), extensions...)
				return testSignedCert(t, publicKey, principals, extensions), nil
			}

			signer, err := certSigner("role", "ubuntu", sign, tt.extensions)
			if err != nil {
				t.Fatalf("certSigner returned error: %v", err)
			}
			if !reflect.DeepEqual(gotExtensions, tt.extensions) {
				t.Fatalf("extensions = %v, want %v", gotExtensions, tt.extensions)
			}

			cert, ok := signer.PublicKey().(*ssh.Certificate)
			if !ok {
				t.Fatalf("public key is %T, want *ssh.Certificate", signer.PublicKey())
			}
			for _, extension := range tt.extensions {
				if _, ok := cert.Permissions.Extensions[extension]; !ok {
					t.Fatalf("signed cert is missing extension %q", extension)
				}
			}
		})
	}
}

func testSignedCert(t *testing.T, publicKey string, principals []string, extensions []string) string {
	t.Helper()

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("create ca signer: %v", err)
	}

	certExtensions := make(map[string]string, len(extensions))
	for _, extension := range extensions {
		certExtensions[extension] = ""
	}
	cert := &ssh.Certificate{
		Key:             pub,
		CertType:        ssh.UserCert,
		ValidPrincipals: principals,
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{
			Extensions: certExtensions,
		},
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(cert))
}
