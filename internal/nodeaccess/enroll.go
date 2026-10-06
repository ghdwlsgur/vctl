package nodeaccess

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// EnrollVM creates a private key locally and exchanges a CSR plus a short-lived
// Nova-signed enrollment grant for a UUID-bound client certificate.
func EnrollVM(ctx context.Context, gatewayURL, tokenFile, instanceUUID, caFile, certFile, keyFile string) error {
	if _, err := VMURI(instanceUUID); err != nil {
		return err
	}
	base, err := agentGatewayURL(gatewayURL)
	if err != nil {
		return err
	}
	info, err := os.Stat(tokenFile)
	if err != nil {
		return fmt.Errorf("stat enrollment token: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("enrollment token file must not be accessible by group or other users")
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return fmt.Errorf("read enrollment token: %w", err)
	}
	grant := strings.TrimSpace(string(token))
	if grant == "" || strings.ContainsAny(grant, "\r\n") {
		return fmt.Errorf("enrollment token is empty or malformed")
	}
	roots, err := loadRoots(caFile)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate VM private key: %w", err)
	}
	identityURI, err := url.Parse(NodeURIScheme + "://" + NodeTrustDomain + "/vm/" + instanceUUID)
	if err != nil {
		return err
	}
	commonName := instanceUUID + ".vm.sre.local"
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName}, URIs: []*url.URL{identityURI},
	}, key)
	if err != nil {
		return fmt.Errorf("create VM certificate signing request: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, err := json.Marshal(map[string]string{"csr": string(csrPEM)})
	if err != nil {
		return err
	}
	endpoint, err := url.Parse(base + "/v1/agent/enroll")
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+grant)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Proxy: nil}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("request VM client certificate: %w", err)
	}
	defer response.Body.Close()
	var result struct {
		Certificate string `json:"certificate"`
		Error       string `json:"error,omitempty"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return fmt.Errorf("decode VM enrollment response")
	}
	if response.StatusCode != http.StatusOK || result.Certificate == "" {
		return fmt.Errorf("VM enrollment was rejected (%s)", response.Status)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("encode VM private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair([]byte(result.Certificate), keyPEM)
	if err != nil {
		return fmt.Errorf("validate VM certificate and private key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse VM certificate: %w", err)
	}
	if err := validateVMCertificate([]byte(result.Certificate), instanceUUID, nil); err != nil {
		return err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify VM certificate chain: %w", err)
	}
	return writeIdentity(certFile, keyFile, &pair)
}
