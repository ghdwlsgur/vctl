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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestGatewayVerifiedNodePollAndOperatorRequest(t *testing.T) {
	_, caKey, caCert := testCA(t)
	nodeURL, _ := url.Parse("spiffe://vctl.local/node/sre-srv-0047")
	clientCert := testLeaf(t, caKey, caCert, x509.ExtKeyUsageClientAuth, []*url.URL{nodeURL}, nil, nil)

	audit := &memoryAudit{}
	gateway, err := NewGateway(testOperatorAuthorizer{}, testNodeAuthorizer{"sre-srv-0047": true}, audit)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()

	agentResult := make(chan error, 1)
	go func() {
		pollRequest := httptest.NewRequest(http.MethodPost, "/v1/agent/poll", nil)
		pollRequest.TLS = verifiedNodeTLS(clientCert.Leaf, caCert)
		poll := httptest.NewRecorder()
		gateway.ServeHTTP(poll, pollRequest)
		if poll.Code != http.StatusOK {
			agentResult <- errUnexpectedStatus("agent poll", poll.Code)
			return
		}
		var request Request
		if err := json.NewDecoder(poll.Body).Decode(&request); err != nil {
			agentResult <- err
			return
		}
		if request.Operation != OperationHostStatus || request.ID != "request-abcdefgh" {
			agentResult <- errUnexpectedRequest(request)
			return
		}
		resultBody, _ := json.Marshal(Result{Version: ProtocolVersion, ID: request.ID, Output: "hostname: sre-srv-0047\nloadavg: 0.10"})
		resultRequest := httptest.NewRequest(http.MethodPost, "/v1/agent/result", bytes.NewReader(resultBody))
		resultRequest.TLS = verifiedNodeTLS(clientCert.Leaf, caCert)
		resultResponse := httptest.NewRecorder()
		gateway.ServeHTTP(resultResponse, resultRequest)
		if resultResponse.Code != http.StatusAccepted {
			agentResult <- errUnexpectedStatus("agent result", resultResponse.Code)
			return
		}
		agentResult <- nil
	}()

	payload, err := json.Marshal(struct {
		Node    string  `json:"node"`
		Request Request `json:"request"`
	}{
		Node: "sre-srv-0047",
		Request: Request{
			Version:   ProtocolVersion,
			ID:        "request-abcdefgh",
			Operation: OperationHostStatus,
			Deadline:  time.Now().Add(30 * time.Second),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/sessions", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer valid-user-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("operator request returned %s: %s", response.Result().Status, response.Body.String())
	}
	var result Result
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Output == "" || result.ID != "request-abcdefgh" {
		t.Fatalf("unexpected operation result: %+v", result)
	}
	if err := <-agentResult; err != nil {
		t.Fatal(err)
	}
	if events := audit.snapshot(); len(events) != 2 || events[0].Outcome != "started" || events[1].Outcome != "completed" {
		t.Fatalf("audit events = %+v, want started and completed", events)
	}
}

func verifiedNodeTLS(leaf, root *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf, root}},
	}
}

type testOperatorAuthorizer struct{}

func (testOperatorAuthorizer) AuthorizeNodeAccess(_ context.Context, credential, node string, _ Operation) (string, error) {
	if credential != "valid-user-token" || node != "sre-srv-0047" {
		return "", context.Canceled
	}
	return "operator@example.test", nil
}

type testNodeAuthorizer map[string]bool

func (a testNodeAuthorizer) AuthorizeNode(_ context.Context, hostname string) error {
	if !a[hostname] {
		return context.Canceled
	}
	return nil
}

type memoryAudit struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *memoryAudit) RecordNodeAccess(_ context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func (a *memoryAudit) snapshot() []AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]AuditEvent(nil), a.events...)
}

func testCA(t *testing.T) (*x509.CertPool, *ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "vctl test CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, key, cert
}

func testLeaf(t *testing.T, caKey *ecdsa.PrivateKey, ca *x509.Certificate, usage x509.ExtKeyUsage, uris []*url.URL, dnsNames []string, ipAddresses []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vctl test leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		URIs:         uris,
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

type statusError string

func (e statusError) Error() string { return string(e) }

func errUnexpectedStatus(stage string, status int) error {
	return statusError(stage + " returned HTTP status " + http.StatusText(status))
}

func errUnexpectedRequest(request Request) error {
	return statusError("unexpected request received by agent: " + request.ID)
}
