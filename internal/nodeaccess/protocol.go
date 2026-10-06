// Package nodeaccess defines the authenticated, typed request boundary used
// by the future outbound node-session channel. It deliberately has no shell
// command field: requests name an operation and carry only operation-specific
// parameters.
package nodeaccess

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	ProtocolVersion = 1
	NodeURIScheme   = "spiffe"
	NodeTrustDomain = "vctl.local"
)

// Operation is a stable, auditable action identifier. Values are intentionally
// narrow so an agent never needs to interpret operator-provided shell text.
type Operation string

const (
	OperationHostStatus     Operation = "host.status"
	OperationContainerList  Operation = "containers.list"
	OperationServiceStatus  Operation = "service.status"
	OperationServiceJournal Operation = "service.journal"
	OperationShellSession   Operation = "shell.session"
)

// Request is sent by the gateway to one authenticated node agent.
type Request struct {
	Version   int               `json:"version"`
	ID        string            `json:"id"`
	Operation Operation         `json:"operation"`
	Params    map[string]string `json:"params,omitempty"`
	Deadline  time.Time         `json:"deadline"`
}

// Result is the bounded result envelope returned by an agent.
type Result struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
	Output  string `json:"output,omitempty"`
	Error   string `json:"error,omitempty"`
}

var (
	requestIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,64}$`)
	servicePattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}$`)
	hostnamePattern  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
	novaUUIDPattern  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// TargetKind identifies the inventory namespace represented by an agent URI.
func TargetKind(identity string) string {
	if novaUUIDPattern.MatchString(identity) {
		return "vm"
	}
	return "host"
}

// Validate rejects unknown operations, extra parameters, and requests that
// cannot be safely bounded. The agent must call this before dispatch.
func (r Request) Validate(now time.Time) error {
	if r.Version != ProtocolVersion {
		return fmt.Errorf("unsupported node access protocol version %d", r.Version)
	}
	if !requestIDPattern.MatchString(r.ID) {
		return fmt.Errorf("invalid request id")
	}
	if r.Deadline.IsZero() || !r.Deadline.After(now) || r.Deadline.After(now.Add(2*time.Minute)) {
		return fmt.Errorf("request deadline must be within the next 2 minutes")
	}
	allowedParams := map[string]bool{}
	switch r.Operation {
	case OperationHostStatus, OperationContainerList:
	case OperationServiceStatus:
		allowedParams["service"] = true
	case OperationServiceJournal:
		allowedParams["service"] = true
		allowedParams["lines"] = true
	default:
		return fmt.Errorf("unsupported operation %q", r.Operation)
	}
	for key := range r.Params {
		if !allowedParams[key] {
			return fmt.Errorf("parameter %q is not allowed for %s", key, r.Operation)
		}
	}
	if r.Operation == OperationServiceStatus || r.Operation == OperationServiceJournal {
		if !servicePattern.MatchString(r.Params["service"]) {
			return fmt.Errorf("service must be a valid systemd unit name")
		}
	}
	if r.Operation == OperationServiceJournal {
		lines := r.Params["lines"]
		if lines == "" {
			return fmt.Errorf("journal lines is required")
		}
		if len(lines) > 4 || strings.Trim(lines, "0123456789") != "" {
			return fmt.Errorf("journal lines must be an integer from 1 to 500")
		}
		var n int
		for _, digit := range lines {
			n = n*10 + int(digit-'0')
		}
		if n < 1 || n > 500 {
			return fmt.Errorf("journal lines must be an integer from 1 to 500")
		}
	}
	return nil
}

// NodeURI returns the canonical URI SAN for an inventory hostname.
func NodeURI(hostname string) (string, error) {
	if !hostnamePattern.MatchString(hostname) {
		return "", fmt.Errorf("invalid inventory hostname")
	}
	return NodeURIScheme + "://" + NodeTrustDomain + "/node/" + hostname, nil
}

// VMURI returns the distinct SPIFFE namespace used by UUID-bound Nova VM
// certificates. Keeping VMs separate from physical host names prevents an
// instance certificate from colliding with an inventory hostname.
func VMURI(instanceUUID string) (string, error) {
	if !novaUUIDPattern.MatchString(instanceUUID) || instanceUUID != strings.ToLower(instanceUUID) {
		return "", fmt.Errorf("invalid Nova instance UUID")
	}
	return NodeURIScheme + "://" + NodeTrustDomain + "/vm/" + instanceUUID, nil
}

// NodeIdentity reads the authenticated node name from a verified client
// certificate. Call only from a TLS server with ClientAuth set to
// RequireAndVerifyClientCert.
func NodeIdentity(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("missing client certificate")
	}
	hostPrefix := NodeURIScheme + "://" + NodeTrustDomain + "/node/"
	vmPrefix := NodeURIScheme + "://" + NodeTrustDomain + "/vm/"
	var identity string
	for _, uri := range cert.URIs {
		value := uri.String()
		if strings.HasPrefix(value, hostPrefix) || strings.HasPrefix(value, vmPrefix) {
			if identity != "" {
				return "", fmt.Errorf("certificate has multiple node identities")
			}
			if strings.HasPrefix(value, vmPrefix) {
				identity = strings.TrimPrefix(value, vmPrefix)
				if !novaUUIDPattern.MatchString(identity) || identity != strings.ToLower(identity) {
					return "", fmt.Errorf("certificate has an invalid Nova VM identity URI SAN")
				}
			} else {
				identity = strings.TrimPrefix(value, hostPrefix)
			}
		}
	}
	if !hostnamePattern.MatchString(identity) {
		return "", fmt.Errorf("certificate has no valid node identity URI SAN")
	}
	return identity, nil
}

// VMIdentity accepts only the VM SPIFFE namespace and returns its Nova UUID.
// Certificate renewal uses this instead of the more general NodeIdentity so
// a physical host certificate can never renew a VM identity.
func VMIdentity(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("missing client certificate")
	}
	prefix := NodeURIScheme + "://" + NodeTrustDomain + "/vm/"
	var identity string
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), prefix) {
			if identity != "" {
				return "", fmt.Errorf("certificate has multiple VM identities")
			}
			identity = strings.TrimPrefix(uri.String(), prefix)
		}
	}
	if !novaUUIDPattern.MatchString(identity) || identity != strings.ToLower(identity) {
		return "", fmt.Errorf("certificate has no valid Nova VM identity URI SAN")
	}
	return identity, nil
}

// AgentTLSConfig configures the node's outbound mTLS connection to the
// gateway. caFile must contain the gateway trust anchor; cert/key are the
// node's short-lived client certificate and private key.
func AgentTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	roots, err := loadRoots(caFile)
	if err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load node mTLS identity: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{cert},
	}, nil
}

// GatewayTLSConfig verifies presented client certificates. It permits
// certificate-free HTTPS clients for the operator API; agent endpoints must
// require a verified certificate and map its URI SAN to inventory.
func GatewayTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load gateway TLS identity: %w", err)
	}
	clients, err := loadRoots(clientCAFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    clients,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %q contains no certificates", path)
	}
	return pool, nil
}
