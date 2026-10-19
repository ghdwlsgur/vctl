package nodeaccess

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ghdwlsgur/vctl/internal/config"
)

const bootstrapTokenLifetime = time.Hour

var projectIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,255}$`)

type novaVendordataRequest struct {
	ProjectID  string            `json:"project-id"`
	InstanceID string            `json:"instance-id"`
	ImageID    string            `json:"image-id"`
	UserData   json.RawMessage   `json:"user-data"`
	Hostname   string            `json:"hostname"`
	Metadata   map[string]string `json:"metadata"`
	BootRoles  string            `json:"boot-roles"`
}

type bootstrapClaims struct {
	Version      int    `json:"v"`
	DeploymentID string `json:"farm"`
	ProjectID    string `json:"project"`
	InstanceID   string `json:"instance"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
}

type cloudFile struct {
	Path        string `yaml:"path"`
	Owner       string `yaml:"owner,omitempty"`
	Permissions string `yaml:"permissions"`
	Content     string `yaml:"content"`
}

type vmVendordataCloudConfig struct {
	WriteFiles []cloudFile `yaml:"write_files"`
	Runcmd     [][]string  `yaml:"runcmd"`
}

// serveVMAgentVendordata is a DynamicJSON target. The response contains a
// signed, short-lived UUID-scoped enrollment grant; it never contains a
// private key or a Vault credential. Nova's auth token is validated against
// the Keystone selected by the farm query parameter.
func (g *Gateway) serveVMAgentVendordata(w http.ResponseWriter, r *http.Request) {
	if g.NovaAuth == nil || len(g.EnrollmentKey) < 32 {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("Nova VM enrollment is not configured"))
		return
	}
	if _, err := agentGatewayURL(g.GatewayURL); err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("VM gateway URL is not configured"))
		return
	}
	farm := strings.TrimSpace(r.URL.Query().Get("farm"))
	token := strings.TrimSpace(r.Header.Get("X-Auth-Token"))
	if farm == "" || token == "" {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("authenticated Nova request and farm are required"))
		return
	}
	var input novaVendordataRequest
	if err := decodeBodyLimit(w, r, &input, 1<<20); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid Nova DynamicJSON request"))
		return
	}
	if !novaUUIDPattern.MatchString(input.InstanceID) || input.InstanceID != strings.ToLower(input.InstanceID) ||
		!projectIDPattern.MatchString(input.ProjectID) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("Nova request has an invalid instance or project id"))
		return
	}
	if err := g.NovaAuth.AuthenticateNova(r.Context(), farm, token); err != nil {
		// The caller gets the generic answer; the reason stays in the log.
		// Without it, the first DynamicJSON rollout could only see a 401 and
		// had no way to tell an unreachable Keystone from a rejected token.
		log.Printf("vendordata: farm %s: Nova service token validation failed: %v", farm, err)
		writeError(w, http.StatusUnauthorized, fmt.Errorf("Nova service token validation failed"))
		return
	}
	now := time.Now().UTC()
	bootstrap, err := signBootstrapToken(g.EnrollmentKey, bootstrapClaims{
		Version: 1, DeploymentID: farm, ProjectID: input.ProjectID,
		InstanceID: input.InstanceID, IssuedAt: now.Unix(), ExpiresAt: now.Add(bootstrapTokenLifetime).Unix(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("create VM enrollment grant"))
		return
	}
	cloudConfig, err := renderVMAgentCloudConfig(g.GatewayURL, input.InstanceID, bootstrap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("render VM enrollment configuration"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, cloudConfig)
}

func (g *Gateway) enrollVMAgent(w http.ResponseWriter, r *http.Request) {
	if g.VMIssuer == nil || len(g.EnrollmentKey) < 32 {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("VM enrollment is not configured"))
		return
	}
	token := bearer(r.Header.Get("Authorization"))
	claims, err := verifyBootstrapToken(g.EnrollmentKey, token, time.Now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, fmt.Errorf("valid VM enrollment grant required"))
		return
	}
	var input struct {
		CSR string `json:"csr"`
	}
	if err := decodeBodyLimit(w, r, &input, maxRequestBody); err != nil || input.CSR == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("a VM certificate signing request is required"))
		return
	}
	certificate, err := g.VMIssuer.SignVMAgentCSR(r.Context(), claims.InstanceID, input.CSR)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("sign VM certificate"))
		return
	}
	if err := validateVMCertificate(certificate, claims.InstanceID, nil); err != nil {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("issuer returned an invalid VM certificate"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, vmAgentCertificate{Certificate: string(certificate)})
}

func (g *Gateway) serveAgentBinary(w http.ResponseWriter, r *http.Request) {
	if g.AgentBinaryPath == "" {
		http.NotFound(w, r)
		return
	}
	info, err := os.Stat(g.AgentBinaryPath)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="vctl-agent"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, g.AgentBinaryPath)
}

func renderVMAgentCloudConfig(gatewayURL, instanceID, enrollmentToken string) (string, error) {
	parsed, err := url.Parse(gatewayURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("gateway URL must be an HTTPS origin")
	}
	gatewayURL = strings.TrimRight(gatewayURL, "/")
	service := `[Unit]
Description=vctl outbound OpenStack VM access agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
Environment=GOMAXPROCS=2
Environment=VCTL_ACCESS_GATEWAY=` + gatewayURL + `
ExecStart=/usr/local/bin/vctl-agent session-agent --gateway ` + gatewayURL + ` --ca /etc/vctl/session-agent/gateway-ca.crt --cert /var/lib/vctl-session-agent/node.crt --key /var/lib/vctl-session-agent/node.key --renew-gateway ` + gatewayURL + `
Restart=always
RestartSec=15
User=root
StateDirectory=vctl-session-agent
StateDirectoryMode=0700
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
RestrictSUIDSGID=true
LockPersonality=true
ReadOnlyPaths=/etc/vctl/session-agent
ReadWritePaths=/var/lib/vctl-session-agent
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CPUQuota=200%
MemoryHigh=512M
MemoryMax=1G
TasksMax=128
LimitCORE=0

[Install]
WantedBy=multi-user.target
`
	script := `set -eu
install -d -m 0700 /var/lib/vctl-session-agent /etc/vctl/session-agent
if command -v curl >/dev/null 2>&1; then
  curl --fail --silent --show-error --location --cacert /etc/vctl/session-agent/gateway-ca.crt ` + gatewayURL + `/v1/agent/binary -o /usr/local/bin/vctl-agent
elif command -v wget >/dev/null 2>&1; then
  wget --ca-certificate=/etc/vctl/session-agent/gateway-ca.crt -O /usr/local/bin/vctl-agent ` + gatewayURL + `/v1/agent/binary
else
  echo 'curl or wget is required to install vctl-agent' >&2
  exit 1
fi
chmod 0755 /usr/local/bin/vctl-agent
/usr/local/bin/vctl-agent node-access enroll-vm --gateway ` + gatewayURL + ` --ca /etc/vctl/session-agent/gateway-ca.crt --token-file /etc/vctl/session-agent/enrollment-token --instance-id ` + instanceID + ` --cert /var/lib/vctl-session-agent/node.crt --key /var/lib/vctl-session-agent/node.key
rm -f /etc/vctl/session-agent/enrollment-token
systemctl daemon-reload
systemctl enable --now vctl-vm-session-agent.service
`
	cloudCfg := vmVendordataCloudConfig{
		WriteFiles: []cloudFile{
			{Path: "/etc/vctl/session-agent/enrollment-token", Owner: "root:root", Permissions: "0600", Content: enrollmentToken},
			{Path: "/etc/vctl/session-agent/gateway-ca.crt", Owner: "root:root", Permissions: "0644", Content: string(config.SRERootCA)},
			{Path: "/etc/systemd/system/vctl-vm-session-agent.service", Owner: "root:root", Permissions: "0644", Content: service},
			{Path: "/usr/local/sbin/vctl-vm-agent-bootstrap", Owner: "root:root", Permissions: "0700", Content: script},
		},
		Runcmd: [][]string{{"/usr/local/sbin/vctl-vm-agent-bootstrap"}},
	}
	data, err := yaml.Marshal(cloudCfg)
	if err != nil {
		return "", err
	}
	return "#cloud-config\n" + string(data), nil
}

func signBootstrapToken(key []byte, claims bootstrapClaims) (string, error) {
	if len(key) < 32 || claims.Version != 1 || claims.InstanceID == "" || claims.ProjectID == "" || claims.DeploymentID == "" {
		return "", fmt.Errorf("invalid enrollment token claims or signing key")
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyBootstrapToken(key []byte, token string, now time.Time) (bootstrapClaims, error) {
	parts := strings.Split(token, ".")
	if len(key) < 32 || len(parts) != 2 || len(parts[0]) > 4096 || len(parts[1]) > 128 {
		return bootstrapClaims{}, fmt.Errorf("invalid token")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return bootstrapClaims{}, fmt.Errorf("invalid token")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return bootstrapClaims{}, fmt.Errorf("invalid token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return bootstrapClaims{}, fmt.Errorf("invalid token")
	}
	var claims bootstrapClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return bootstrapClaims{}, fmt.Errorf("invalid token")
	}
	if claims.Version != 1 || claims.InstanceID != strings.ToLower(claims.InstanceID) || !novaUUIDPattern.MatchString(claims.InstanceID) ||
		!projectIDPattern.MatchString(claims.ProjectID) || claims.DeploymentID == "" || claims.IssuedAt > now.Add(time.Minute).Unix() ||
		claims.ExpiresAt <= now.Unix() || claims.ExpiresAt-claims.IssuedAt > int64(bootstrapTokenLifetime.Seconds()) {
		return bootstrapClaims{}, fmt.Errorf("expired or invalid token")
	}
	return claims, nil
}

func validateVMCertificate(certificatePEM []byte, instanceUUID string, csr *x509.CertificateRequest) error {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("missing X.509 certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	identity, err := VMIdentity(leaf)
	if err != nil || identity != instanceUUID {
		return fmt.Errorf("certificate VM identity mismatch")
	}
	if leaf.Subject.CommonName != instanceUUID+".vm.sre.local" || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return fmt.Errorf("certificate common name or validity is incorrect")
	}
	clientAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		clientAuth = clientAuth || usage == x509.ExtKeyUsageClientAuth
	}
	if !clientAuth {
		return fmt.Errorf("certificate is not valid for client authentication")
	}
	if csr != nil && !bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("certificate public key does not match the signing request")
	}
	return nil
}
