package nodeaccess

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

const (
	maxRequestBody   = 16 << 10
	maxResultBody    = 2 << 20
	maxAgentWait     = 25 * time.Second
	maxInFlight      = 256
	maxShellSessions = 32
	maxShellLifetime = 8 * time.Hour
)

// OperatorAuthorizer must validate the presented user credential against the
// identity provider and check the caller's node-access grant. It returns the
// stable operator identity used by the audit hook. Implementations must fail
// closed; the gateway has no permissive default.
type OperatorAuthorizer interface {
	AuthorizeNodeAccess(ctx context.Context, credential, node string, operation Operation) (operator string, err error)
}

// NodeAuthorizer maps the certificate URI SAN to inventory and rejects nodes
// that are unknown, disabled, or revoked.
type NodeAuthorizer interface {
	AuthorizeNode(ctx context.Context, hostname string) error
}

// AuditRecorder stores lifecycle metadata. Implementations should not store
// operation output. Returning an error prevents the operation from proceeding
// (start audit) or causes the session request to fail (completion audit).
type AuditRecorder interface {
	RecordNodeAccess(ctx context.Context, event AuditEvent) error
}

// VMAgentCertificateIssuer signs a replacement identity for one VM UUID.
// Implementations must use a role constrained to the VM certificate namespace.
type VMAgentCertificateIssuer interface {
	SignVMAgentCSR(ctx context.Context, instanceUUID, csrPEM string) (certificatePEM []byte, err error)
}

// NovaDynamicAuthenticator validates the service token Nova attached to a
// DynamicJSON request against the named farm's Keystone.
type NovaDynamicAuthenticator interface {
	AuthenticateNova(ctx context.Context, deploymentID, token string) error
}

type AuditEvent struct {
	RequestID  string
	Operator   string
	Node       string
	TargetKind string
	Operation  Operation
	StartedAt  time.Time
	EndedAt    time.Time
	Outcome    string
}

type Gateway struct {
	Operators     OperatorAuthorizer
	Nodes         NodeAuthorizer
	Audit         AuditRecorder
	NodeRoots     *x509.CertPool // optional CA for a verified ingress-forwarded client certificate
	VMIssuer      VMAgentCertificateIssuer
	NovaAuth      NovaDynamicAuthenticator
	EnrollmentKey []byte
	GatewayURL    string
	// GatewayAddress, when set, is pinned in a guest's /etc/hosts for the
	// GatewayURL host if the guest cannot resolve it. See
	// renderVMAgentCloudConfig.
	GatewayAddress  string
	AgentBinaryPath string

	mu      sync.Mutex
	queues  map[string]chan Request
	pending map[string]pendingRequest
	agents  map[string]*shellPeer
	shells  map[string]*shellBridge
	closed  chan struct{}
}

type pendingRequest struct {
	node   string
	result chan Result
}

type shellBridge struct {
	id     string
	output chan ShellMessage
}

// NewGateway creates a fail-closed in-memory request broker. The broker is
// intended to live behind a TLS listener configured with GatewayTLSConfig.
// Outstanding requests are lost if the process restarts; session history is
// recorded through the supplied audit store.
func NewGateway(operators OperatorAuthorizer, nodes NodeAuthorizer, audit AuditRecorder, nodeRoots ...*x509.CertPool) (*Gateway, error) {
	if operators == nil || nodes == nil || audit == nil {
		return nil, fmt.Errorf("operator authorization, node authorization, and audit recorder are required")
	}
	gateway := &Gateway{
		Operators: operators,
		Nodes:     nodes,
		Audit:     audit,
		queues:    make(map[string]chan Request),
		pending:   make(map[string]pendingRequest),
		agents:    make(map[string]*shellPeer),
		shells:    make(map[string]*shellBridge),
		closed:    make(chan struct{}),
	}
	if len(nodeRoots) > 0 {
		gateway.NodeRoots = nodeRoots[0]
	}
	return gateway, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch r.URL.Path {
	case "/v1/agent/poll":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		g.poll(w, r)
	case "/v1/agent/result":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		g.acceptResult(w, r)
	case "/v1/agent/renew":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		g.renewVMAgent(w, r)
	case "/v1/agent/enroll":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		g.enrollVMAgent(w, r)
	case "/v1/agent/binary":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		g.serveAgentBinary(w, r)
	case "/v1/vendordata":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		g.serveVMAgentVendordata(w, r)
	case "/v1/sessions":
		if r.Method != http.MethodPost {
			methodNotAllowed(w)
			return
		}
		g.startSession(w, r)
	case "/v1/agent/stream":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		g.agentShellStream(w, r)
	case "/v1/sessions/shell":
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		g.startShell(w, r)
	default:
		http.NotFound(w, r)
	}
}

type vmAgentCertificate struct {
	Certificate string `json:"certificate"`
}

func (g *Gateway) renewVMAgent(w http.ResponseWriter, r *http.Request) {
	if g.VMIssuer == nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("VM certificate renewal is not configured"))
		return
	}
	cert, err := g.requestPeerCertificate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	instanceUUID, err := VMIdentity(cert)
	if err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}
	if err := g.Nodes.AuthorizeNode(r.Context(), instanceUUID); err != nil {
		writeError(w, http.StatusForbidden, fmt.Errorf("VM is not authorized"))
		return
	}
	var input struct {
		CSR string `json:"csr"`
	}
	if err := decodeBodyLimit(w, r, &input, maxRequestBody); err != nil || input.CSR == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("a valid VM certificate signing request is required"))
		return
	}
	certificate, err := g.VMIssuer.SignVMAgentCSR(r.Context(), instanceUUID, input.CSR)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("sign VM certificate"))
		return
	}
	leafBlock, _ := pem.Decode(certificate)
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("issuer returned an invalid VM certificate"))
		return
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("issuer returned an invalid VM certificate"))
		return
	}
	issuedUUID, err := VMIdentity(leaf)
	if err != nil || issuedUUID != instanceUUID {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("issuer returned a certificate for a different VM"))
		return
	}
	writeJSON(w, http.StatusOK, vmAgentCertificate{Certificate: string(certificate)})
}

func (g *Gateway) poll(w http.ResponseWriter, r *http.Request) {
	node, err := g.requestNodeIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if err := g.Nodes.AuthorizeNode(r.Context(), node); err != nil {
		writeError(w, http.StatusForbidden, fmt.Errorf("node is not authorized"))
		return
	}
	queue := g.queue(node)
	timer := time.NewTimer(maxAgentWait)
	defer timer.Stop()
	select {
	case request := <-queue:
		writeJSON(w, http.StatusOK, request)
	case <-timer.C:
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
	case <-g.closed:
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("gateway is shutting down"))
	}
}

func (g *Gateway) acceptResult(w http.ResponseWriter, r *http.Request) {
	node, err := g.requestNodeIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if err := g.Nodes.AuthorizeNode(r.Context(), node); err != nil {
		writeError(w, http.StatusForbidden, fmt.Errorf("node is not authorized"))
		return
	}
	var result Result
	if err := decodeBodyLimit(w, r, &result, maxResultBody); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if result.Version != ProtocolVersion || !requestIDPattern.MatchString(result.ID) || len(result.Output) > maxResultBytes || len(result.Error) > 8<<10 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid or oversized result"))
		return
	}
	g.mu.Lock()
	pending, ok := g.pending[result.ID]
	if !ok || pending.node != node {
		g.mu.Unlock()
		writeError(w, http.StatusNotFound, fmt.Errorf("request not found for this node"))
		return
	}
	delete(g.pending, result.ID)
	g.mu.Unlock()
	select {
	case pending.result <- result:
		w.WriteHeader(http.StatusAccepted)
	default:
		writeError(w, http.StatusConflict, fmt.Errorf("request already completed"))
	}
}

func (g *Gateway) startSession(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Node    string  `json:"node"`
		Request Request `json:"request"`
	}
	if err := decodeBody(w, r, &input); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if _, err := NodeURI(input.Node); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid target node"))
		return
	}
	if err := input.Request.Validate(time.Now()); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	credential := bearer(r.Header.Get("Authorization"))
	if credential == "" {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("bearer credential required"))
		return
	}
	operator, err := g.Operators.AuthorizeNodeAccess(r.Context(), credential, input.Node, input.Request.Operation)
	if err != nil || operator == "" {
		writeError(w, http.StatusForbidden, fmt.Errorf("operator is not authorized for this node operation"))
		return
	}
	if err := g.Nodes.AuthorizeNode(r.Context(), input.Node); err != nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("target node is not available"))
		return
	}
	started := time.Now().UTC()
	event := AuditEvent{RequestID: input.Request.ID, Operator: operator, Node: input.Node, TargetKind: TargetKind(input.Node), Operation: input.Request.Operation, StartedAt: started, Outcome: "started"}
	job := pendingRequest{node: input.Node, result: make(chan Result, 1)}
	g.mu.Lock()
	if len(g.pending) >= maxInFlight {
		g.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("gateway is at session capacity"))
		return
	}
	if _, exists := g.pending[input.Request.ID]; exists {
		g.mu.Unlock()
		writeError(w, http.StatusConflict, fmt.Errorf("request id is already active"))
		return
	}
	queue := g.queueLocked(input.Node)
	g.pending[input.Request.ID] = job
	g.mu.Unlock()
	if err := g.Audit.RecordNodeAccess(r.Context(), event); err != nil {
		g.removePending(input.Request.ID)
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("could not record access audit"))
		return
	}
	select {
	case queue <- input.Request:
	case <-r.Context().Done():
		g.removePending(input.Request.ID)
		return
	case <-g.closed:
		g.removePending(input.Request.ID)
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("gateway is shutting down"))
		return
	}
	remaining := time.Until(input.Request.Deadline)
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case result := <-job.result:
		ended := time.Now().UTC()
		outcome := "completed"
		if result.Error != "" {
			outcome = "failed"
		}
		event.EndedAt, event.Outcome = ended, outcome
		if err := g.Audit.RecordNodeAccess(r.Context(), event); err != nil {
			writeError(w, http.StatusServiceUnavailable, fmt.Errorf("could not record completion audit"))
			return
		}
		writeJSON(w, http.StatusOK, result)
	case <-timer.C:
		g.removePending(input.Request.ID)
		event.EndedAt, event.Outcome = time.Now().UTC(), "timeout"
		_ = g.Audit.RecordNodeAccess(context.Background(), event)
		writeError(w, http.StatusGatewayTimeout, fmt.Errorf("node operation timed out"))
	case <-r.Context().Done():
		g.removePending(input.Request.ID)
		event.EndedAt, event.Outcome = time.Now().UTC(), "cancelled"
		_ = g.Audit.RecordNodeAccess(context.Background(), event)
	case <-g.closed:
		g.removePending(input.Request.ID)
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("gateway is shutting down"))
	}
}

func (g *Gateway) agentShellStream(w http.ResponseWriter, r *http.Request) {
	node, err := g.requestNodeIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	if err := g.Nodes.AuthorizeNode(r.Context(), node); err != nil {
		writeError(w, http.StatusForbidden, fmt.Errorf("agent is not authorized"))
		return
	}
	handler := websocket.Handler(func(conn *websocket.Conn) {
		conn.MaxPayloadBytes = maxShellFrame
		peer := &shellPeer{conn: conn}
		g.mu.Lock()
		previous := g.agents[node]
		g.agents[node] = peer
		g.mu.Unlock()
		if previous != nil && previous != peer {
			_ = previous.conn.Close()
		}
		defer func() {
			g.mu.Lock()
			if g.agents[node] == peer {
				delete(g.agents, node)
				if active := g.shells[node]; active != nil {
					select {
					case active.output <- ShellMessage{Type: "error", SessionID: active.id, Error: "VM agent disconnected"}:
					default:
					}
				}
			}
			g.mu.Unlock()
			_ = conn.Close()
		}()
		for {
			message, err := receiveShellMessage(conn)
			if err != nil {
				return
			}
			if message.Type == "ready" || message.Type == "heartbeat" {
				continue
			}
			g.mu.Lock()
			active := g.shells[node]
			g.mu.Unlock()
			if active == nil || message.SessionID != active.id {
				continue
			}
			select {
			case active.output <- message:
			case <-r.Context().Done():
				return
			}
		}
	})
	handler.ServeHTTP(w, r)
}

func (g *Gateway) startShell(w http.ResponseWriter, r *http.Request) {
	node := r.URL.Query().Get("node")
	if _, err := NodeURI(node); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("valid host name or VM UUID is required"))
		return
	}
	if TargetKind(node) != "vm" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("interactive shell sessions are enabled for OpenStack VM identities only"))
		return
	}
	credential := bearer(r.Header.Get("Authorization"))
	if credential == "" {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("bearer credential required"))
		return
	}
	operator, err := g.Operators.AuthorizeNodeAccess(r.Context(), credential, node, OperationShellSession)
	if err != nil || operator == "" {
		writeError(w, http.StatusForbidden, fmt.Errorf("operator is not authorized for shell access"))
		return
	}
	if err := g.Nodes.AuthorizeNode(r.Context(), node); err != nil {
		writeError(w, http.StatusNotFound, fmt.Errorf("target is not an active inventory host or VM"))
		return
	}
	g.mu.Lock()
	agent := g.agents[node]
	if agent == nil {
		g.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("target agent is not connected"))
		return
	}
	if g.shells[node] != nil {
		g.mu.Unlock()
		writeError(w, http.StatusConflict, fmt.Errorf("target already has an active shell session"))
		return
	}
	if len(g.shells) >= maxShellSessions {
		g.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("gateway shell capacity is full"))
		return
	}
	sessionID, err := newShellSessionID()
	if err != nil {
		g.mu.Unlock()
		writeError(w, http.StatusInternalServerError, fmt.Errorf("could not create session id"))
		return
	}
	bridge := &shellBridge{id: sessionID, output: make(chan ShellMessage, 32)}
	g.shells[node] = bridge
	g.mu.Unlock()

	started := time.Now().UTC()
	event := AuditEvent{RequestID: sessionID, Operator: operator, Node: node, TargetKind: TargetKind(node), Operation: OperationShellSession, StartedAt: started, Outcome: "started"}
	if err := g.Audit.RecordNodeAccess(r.Context(), event); err != nil {
		g.finishShell(node, bridge, agent)
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("could not record shell audit"))
		return
	}
	sessionOutcome := "completed"
	sessionFinished := false
	handler := websocket.Handler(func(client *websocket.Conn) {
		client.MaxPayloadBytes = maxShellFrame
		if err := agent.send(ShellMessage{Type: "start", SessionID: sessionID, Columns: 80, Rows: 24}); err != nil {
			_ = websocket.JSON.Send(client, ShellMessage{Type: "error", SessionID: sessionID, Error: "could not start VM shell"})
			return
		}
		inputErrors := make(chan error, 1)
		go func() {
			for {
				message, err := receiveShellMessage(client)
				if err != nil {
					inputErrors <- err
					return
				}
				if message.Type != "input" && message.Type != "resize" && message.Type != "close" {
					inputErrors <- fmt.Errorf("unknown shell input message")
					return
				}
				message.SessionID = sessionID
				if err := agent.send(message); err != nil {
					inputErrors <- err
					return
				}
				if message.Type == "close" {
					inputErrors <- io.EOF
					return
				}
			}
		}()
		startTimer := time.NewTimer(20 * time.Second)
		defer startTimer.Stop()
		sessionTimer := time.NewTimer(maxShellLifetime)
		defer sessionTimer.Stop()
		startedAgent := false
		for {
			select {
			case message := <-bridge.output:
				if message.Type == "started" {
					startedAgent = true
				}
				if message.Type == "error" {
					sessionOutcome = "failed"
				}
				if message.Type == "exit" || message.Type == "error" {
					sessionFinished = true
				}
				if err := websocket.JSON.Send(client, message); err != nil || message.Type == "exit" || message.Type == "error" {
					return
				}
			case <-startTimer.C:
				if !startedAgent {
					_ = websocket.JSON.Send(client, ShellMessage{Type: "error", SessionID: sessionID, Error: "VM agent did not open a PTY within 20 seconds"})
					return
				}
			case <-sessionTimer.C:
				sessionOutcome = "timeout"
				_ = agent.send(ShellMessage{Type: "close", SessionID: sessionID})
				return
			case <-inputErrors:
				return
			case <-r.Context().Done():
				return
			case <-g.closed:
				return
			}
		}
	})
	handler.ServeHTTP(w, r)
	if r.Context().Err() != nil && sessionOutcome == "completed" && !sessionFinished {
		sessionOutcome = "disconnected"
	}
	g.finishShell(node, bridge, agent)
	event.EndedAt, event.Outcome = time.Now().UTC(), sessionOutcome
	if err := g.Audit.RecordNodeAccess(context.Background(), event); err != nil {
		log.Printf("node-access shell completion audit failed for session %s: %v", sessionID, err)
	}
}

func (g *Gateway) finishShell(node string, bridge *shellBridge, agent *shellPeer) {
	g.mu.Lock()
	if g.shells[node] == bridge {
		delete(g.shells, node)
	}
	g.mu.Unlock()
	_ = agent.send(ShellMessage{Type: "close", SessionID: bridge.id})
}

func newShellSessionID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

// Close stops outstanding long polls and session requests. It is safe to call
// more than once.
func (g *Gateway) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	select {
	case <-g.closed:
	default:
		close(g.closed)
	}
}

func (g *Gateway) queue(node string) chan Request {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.queueLocked(node)
}

func (g *Gateway) queueLocked(node string) chan Request {
	if queue := g.queues[node]; queue != nil {
		return queue
	}
	queue := make(chan Request, maxInFlight)
	g.queues[node] = queue
	return queue
}

func (g *Gateway) removePending(id string) { g.mu.Lock(); delete(g.pending, id); g.mu.Unlock() }

func (g *Gateway) requestNodeIdentity(r *http.Request) (string, error) {
	cert, err := g.requestPeerCertificate(r)
	if err != nil {
		return "", err
	}
	return NodeIdentity(cert)
}

func (g *Gateway) requestPeerCertificate(r *http.Request) (*x509.Certificate, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.VerifiedChains) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}
	// Ingress-nginx terminates the external TLS connection and forwards its
	// verified client certificate as a URL-escaped PEM header. This path is
	// enabled only when the gateway has a dedicated node CA mounted; the
	// Kubernetes NetworkPolicy must restrict the service to ingress-nginx.
	if g.NodeRoots != nil {
		encoded := r.Header.Get("ssl-client-cert")
		if encoded != "" {
			certPEM, err := url.QueryUnescape(encoded)
			if err != nil {
				return nil, fmt.Errorf("invalid forwarded node certificate")
			}
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("invalid forwarded node certificate")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid forwarded node certificate")
			}
			if _, err := cert.Verify(x509.VerifyOptions{Roots: g.NodeRoots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				return nil, fmt.Errorf("forwarded node certificate is not trusted")
			}
			return cert, nil
		}
	}
	return nil, fmt.Errorf("verified node client certificate required")
}

func bearer(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	return decodeBodyLimit(w, r, dst, maxRequestBody)
}

func decodeBodyLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func methodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Allow", http.MethodPost)
	writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
}
