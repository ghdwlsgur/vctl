package nodeaccess

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

const testVMIdentity = "121b94fa-98b5-40c5-8998-22e027bacf26"

type shellTestAdapters struct {
	mu     sync.Mutex
	events []AuditEvent
}

func (a *shellTestAdapters) AuthorizeNodeAccess(_ context.Context, credential, node string, operation Operation) (string, error) {
	if credential != "test-token" || node != testVMIdentity || operation != OperationShellSession {
		return "", context.Canceled
	}
	return "local-test-operator", nil
}

func (a *shellTestAdapters) AuthorizeNode(_ context.Context, node string) error {
	if node != testVMIdentity {
		return context.Canceled
	}
	return nil
}

func (a *shellTestAdapters) RecordNodeAccess(_ context.Context, event AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func TestGatewayShellSessionRunsLinuxPTYOverAgentStream(t *testing.T) {
	adapter := &shellTestAdapters{}
	gateway, err := NewGateway(adapter, adapter, adapter)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()

	clientCA, clientCert := shellTestClientCertificate(t)
	server := httptest.NewUnstartedServer(gateway)
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: clientCA, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	serverCert := server.Certificate()
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(serverCert)
	agentTLS := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: serverRoots, Certificates: []tls.Certificate{clientCert}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := server.URL
	agentDone := make(chan error, 1)
	agentErrors := make(chan error, 16)
	go func() {
		agentDone <- (&SessionAgent{GatewayURL: base, TLS: agentTLS, OnError: func(err error) {
			select {
			case agentErrors <- err:
			default:
			}
		}}).Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		gateway.mu.Lock()
		connected := gateway.agents[testVMIdentity] != nil
		gateway.mu.Unlock()
		if connected {
			break
		}
		if time.Now().After(deadline) {
			select {
			case err := <-agentErrors:
				t.Fatalf("VM agent did not connect to the local gateway: %v", err)
			default:
				t.Fatal("VM agent did not connect to the local gateway")
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	shellURL, err := url.Parse(server.URL + "/v1/sessions/shell")
	if err != nil {
		t.Fatal(err)
	}
	shellURL.Scheme = "wss"
	query := shellURL.Query()
	query.Set("node", testVMIdentity)
	shellURL.RawQuery = query.Encode()
	config, err := websocket.NewConfig(shellURL.String(), "https://local.operator")
	if err != nil {
		t.Fatal(err)
	}
	config.Header.Set("Authorization", "Bearer test-token")
	config.TlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: serverRoots}
	operator, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("open local operator WebSocket: %v", err)
	}
	defer operator.Close()
	operator.MaxPayloadBytes = maxShellFrame

	command := `printf 'VCTL_BASH_%s\n' "${BASH_VERSION:+OK}"; exit` + "\n"
	if err := websocket.JSON.Send(operator, ShellMessage{Type: "input", Data: []byte(command)}); err != nil {
		t.Fatalf("send shell input: %v", err)
	}
	var output strings.Builder
	seenStarted, seenExit := false, false
	readMessages := make(chan error, 1)
	go func() {
		for {
			var message ShellMessage
			if err := websocket.JSON.Receive(operator, &message); err != nil {
				readMessages <- err
				return
			}
			switch message.Type {
			case "started":
				seenStarted = true
			case "output":
				output.Write(message.Data)
			case "exit":
				seenExit = true
				readMessages <- nil
				return
			case "error":
				readMessages <- context.DeadlineExceeded
				return
			}
		}
	}()
	select {
	case err := <-readMessages:
		if err != nil {
			t.Fatalf("read local PTY session: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("local PTY session did not exit")
	}
	if !seenStarted || !seenExit || !strings.Contains(output.String(), "VCTL_BASH_OK") {
		t.Fatalf("incomplete PTY exchange: started=%v exit=%v output=%q", seenStarted, seenExit, output.String())
	}

	auditDeadline := time.Now().Add(2 * time.Second)
	for {
		adapter.mu.Lock()
		complete := len(adapter.events) == 2
		events := append([]AuditEvent(nil), adapter.events...)
		adapter.mu.Unlock()
		if complete {
			if events[0].Outcome != "started" || events[1].Outcome != "completed" || events[0].TargetKind != "vm" {
				t.Fatalf("unexpected local shell audit lifecycle: %+v", events)
			}
			break
		}
		if time.Now().After(auditDeadline) {
			t.Fatalf("shell completion audit was not recorded: %+v", events)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func shellTestClientCertificate(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := NodeURI(testVMIdentity)
	if err != nil {
		t.Fatal(err)
	}
	uriSAN, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "local-test-vm.sre.local"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{uriSAN}}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := x509.ParseCertificate(clientDER)
	if err != nil {
		t.Fatal(err)
	}
	return roots, tls.Certificate{Certificate: [][]byte{clientDER}, PrivateKey: clientKey, Leaf: clientCert}
}
