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
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ghdwlsgur/vctl/internal/config"
)

const (
	certificateRenewBefore = 10 * 24 * time.Hour
	certificateRenewEvery  = 12 * time.Hour
)

// CertificateRenewer mints a replacement node identity through a host-specific
// Vault AppRole and publishes it to the agent only after both files are written.
type CertificateRenewer struct {
	GatewayURL string
	TLS        *tls.Config
	VaultAddr  string
	RoleIDFile string
	SecretFile string
	PKIMount   string
	PKIRole    string
	CommonName string
	URISAN     string
	CertFile   string
	KeyFile    string
	Now        func() time.Time
	Client     *http.Client
}

func (r *CertificateRenewer) Run(ctx context.Context, identity *atomic.Pointer[tls.Certificate], onError func(error)) {
	check := func() {
		cert := identity.Load()
		if cert == nil || len(cert.Certificate) == 0 {
			if onError != nil {
				onError(fmt.Errorf("node mTLS identity is unavailable for renewal"))
			}
			return
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("parse current node certificate: %w", err))
			}
			return
		}
		now := time.Now
		if r.Now != nil {
			now = r.Now
		}
		if leaf.NotAfter.Sub(now()) > certificateRenewBefore {
			return
		}
		updated, err := r.issue(ctx, cert)
		if err == nil {
			err = writeIdentity(r.CertFile, r.KeyFile, updated)
		}
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("renew node mTLS certificate: %w", err))
			}
			return
		}
		identity.Store(updated)
	}
	check()
	ticker := time.NewTicker(certificateRenewEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}

func (r *CertificateRenewer) issue(ctx context.Context, current *tls.Certificate) (*tls.Certificate, error) {
	if r.GatewayURL != "" {
		return r.issueThroughGateway(ctx, current)
	}
	if r.VaultAddr == "" || r.RoleIDFile == "" || r.SecretFile == "" || r.PKIMount == "" || r.PKIRole == "" || r.CommonName == "" || r.URISAN == "" {
		return nil, fmt.Errorf("Vault renewal settings are incomplete")
	}
	roleID, err := readCredential(r.RoleIDFile)
	if err != nil {
		return nil, fmt.Errorf("read Vault role id: %w", err)
	}
	secretID, err := readCredential(r.SecretFile)
	if err != nil {
		return nil, fmt.Errorf("read Vault secret id: %w", err)
	}
	base := strings.TrimRight(r.VaultAddr, "/")
	client := r.Client
	if client == nil {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(config.SRERootCA) {
			return nil, fmt.Errorf("embedded SRE CA bundle is invalid")
		}
		client = &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	}
	login, err := vaultPost(ctx, client, base+"/v1/auth/approle/login", map[string]string{"role_id": roleID, "secret_id": secretID}, "")
	if err != nil {
		return nil, fmt.Errorf("authenticate to Vault: %w", err)
	}
	var auth struct {
		ClientToken string `json:"client_token"`
	}
	if err := json.Unmarshal(login.Auth, &auth); err != nil || auth.ClientToken == "" {
		return nil, fmt.Errorf("Vault AppRole login returned no token")
	}
	issued, err := vaultPost(ctx, client, base+"/v1/"+strings.Trim(r.PKIMount, "/")+"/issue/"+r.PKIRole, map[string]string{
		"common_name": r.CommonName, "uri_sans": r.URISAN, "ttl": "720h", "format": "pem",
	}, auth.ClientToken)
	if err != nil {
		return nil, fmt.Errorf("request replacement certificate: %w", err)
	}
	var data struct {
		Certificate string   `json:"certificate"`
		PrivateKey  string   `json:"private_key"`
		CAChain     []string `json:"ca_chain"`
	}
	if err := json.Unmarshal(issued.Data, &data); err != nil {
		return nil, fmt.Errorf("decode issued certificate: %w", err)
	}
	if data.Certificate == "" || data.PrivateKey == "" {
		return nil, fmt.Errorf("Vault returned an incomplete certificate")
	}
	certPEM := data.Certificate + "\n"
	for _, ca := range data.CAChain {
		certPEM += strings.TrimSpace(ca) + "\n"
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(data.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("validate issued certificate and key: %w", err)
	}
	return &cert, nil
}

func (r *CertificateRenewer) issueThroughGateway(ctx context.Context, current *tls.Certificate) (*tls.Certificate, error) {
	if r.TLS == nil || current == nil || len(current.Certificate) == 0 {
		return nil, fmt.Errorf("gateway renewal requires the current VM certificate")
	}
	leaf, err := x509.ParseCertificate(current.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse current VM certificate: %w", err)
	}
	instanceUUID, err := VMIdentity(leaf)
	if err != nil {
		return nil, fmt.Errorf("current certificate is not a VM identity: %w", err)
	}
	identityURI, err := url.Parse(NodeURIScheme + "://" + NodeTrustDomain + "/vm/" + instanceUUID)
	if err != nil {
		return nil, err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate replacement VM key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: instanceUUID + ".vm.sre.local"}, URIs: []*url.URL{identityURI},
	}, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create replacement VM certificate request: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, err := json.Marshal(map[string]string{"csr": string(csrPEM)})
	if err != nil {
		return nil, err
	}
	base, err := agentGatewayURL(r.GatewayURL)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/agent/renew", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	tlsConfig := r.TLS.Clone()
	tlsConfig.Certificates = nil
	if tlsConfig.GetClientCertificate == nil {
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return current, nil }
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true, Proxy: nil}
	client := r.Client
	if client == nil {
		client = &http.Client{Transport: transport, Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	} else {
		transport.CloseIdleConnections()
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request VM certificate renewal from gateway: %w", err)
	}
	defer response.Body.Close()
	var result struct {
		Certificate string `json:"certificate"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode gateway VM renewal response")
	}
	if response.StatusCode != http.StatusOK || result.Certificate == "" {
		return nil, fmt.Errorf("gateway rejected VM certificate renewal (%s)", response.Status)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	updated, err := tls.X509KeyPair([]byte(result.Certificate), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("validate gateway replacement certificate and key: %w", err)
	}
	newLeaf, err := x509.ParseCertificate(updated.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := validateVMCertificate([]byte(result.Certificate), instanceUUID, nil); err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, newLeaf.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("gateway certificate does not match the replacement key")
	}
	if _, err := newLeaf.Verify(x509.VerifyOptions{Roots: r.TLS.RootCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, fmt.Errorf("verify gateway replacement certificate chain: %w", err)
	}
	return &updated, nil
}

type vaultResponse struct {
	Auth   json.RawMessage `json:"auth"`
	Data   json.RawMessage `json:"data"`
	Errors []string        `json:"errors"`
}

func vaultPost(ctx context.Context, client *http.Client, endpoint string, payload any, token string) (vaultResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return vaultResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return vaultResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return vaultResponse{}, err
	}
	defer resp.Body.Close()
	var result vaultResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return result, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("Vault returned %s: %s", resp.Status, strings.Join(result.Errors, "; "))
	}
	return result, nil
}

func readCredential(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(b))
	if value == "" {
		return "", fmt.Errorf("credential file is empty")
	}
	return value, nil
}

func writeIdentity(certPath, keyPath string, cert *tls.Certificate) error {
	if len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 || cert.PrivateKey == nil {
		return fmt.Errorf("replacement certificate is incomplete")
	}
	var certPEM []byte
	for _, der := range cert.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("encode replacement private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeAtomic(certPath, certPEM, 0o600); err != nil {
		return fmt.Errorf("write replacement certificate: %w", err)
	}
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write replacement key: %w", err)
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".vctl-node-identity-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
