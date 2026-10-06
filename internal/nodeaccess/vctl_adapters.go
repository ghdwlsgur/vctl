package nodeaccess

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// VCTLAdapters connect the gateway policy hooks to this installation's Vault
// and Postgres backends. The service Vault token supplies only inventory read
// and append-only audit DB roles; operator tokens are looked up independently.
type VCTLAdapters struct{ App *app.App }

func (a VCTLAdapters) SignVMAgentCSR(ctx context.Context, instanceUUID, csr string) ([]byte, error) {
	if a.App == nil || a.App.Vault == nil {
		return nil, fmt.Errorf("gateway Vault issuer is not configured")
	}
	return a.App.Vault.SignVMAgentCSR(ctx, instanceUUID, csr)
}

func (a VCTLAdapters) AuthenticateNova(ctx context.Context, deploymentID, serviceToken string) error {
	if a.App == nil {
		return fmt.Errorf("gateway app is not configured")
	}
	if strings.TrimSpace(serviceToken) == "" || strings.ContainsAny(serviceToken, "\r\n") {
		return fmt.Errorf("Nova service token is missing or malformed")
	}
	st, err := a.App.OpenStore(ctx, app.PurposeInventoryRead)
	if err != nil {
		return err
	}
	deployments, err := st.Deployments(ctx)
	st.Close()
	if err != nil {
		return fmt.Errorf("list registered OpenStack farms: %w", err)
	}
	known := false
	for _, deployment := range deployments {
		if deployment.ID == deploymentID && deployment.State == "active" {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("farm is not registered and active")
	}
	// Farm IDs are normalized Keystone host:port values from inventory, not
	// caller-supplied URLs. Send service tokens only over verified HTTPS.
	endpoint, err := url.Parse("https://" + deploymentID + "/v3/auth/tokens")
	if err != nil || endpoint.Host != deploymentID || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("registered farm has an invalid Keystone endpoint")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(config.SRERootCA) && len(config.SRERootCA) > 0 {
		return fmt.Errorf("embedded SRE certificate authority is invalid")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Proxy: nil}
	client := &http.Client{
		Transport: transport, Timeout: 4 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return fmt.Errorf("build Keystone token validation request")
	}
	request.Header.Set("X-Auth-Token", serviceToken)
	request.Header.Set("X-Subject-Token", serviceToken)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("validate Nova service token with farm Keystone: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("farm Keystone rejected Nova service token (%s)", response.Status)
	}
	var result struct {
		Token struct {
			ExpiresAt string `json:"expires_at"`
			User      struct {
				Name string `json:"name"`
			} `json:"user"`
			Project struct {
				ID string `json:"id"`
			} `json:"project"`
			Roles []struct {
				Name string `json:"name"`
			} `json:"roles"`
		} `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(nil, response.Body, 64<<10)).Decode(&result); err != nil {
		return fmt.Errorf("decode Keystone token validation response")
	}
	username := strings.TrimSpace(os.Getenv("VCTL_NOVA_SERVICE_USERNAME"))
	if username == "" {
		username = "nova"
	}
	admin := false
	for _, role := range result.Token.Roles {
		admin = admin || role.Name == "admin"
	}
	expires, err := time.Parse(time.RFC3339Nano, result.Token.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || result.Token.User.Name != username || result.Token.Project.ID == "" || !admin {
		return fmt.Errorf("Keystone token is not an active Nova service identity")
	}
	return nil
}

func (a VCTLAdapters) AuthorizeNodeAccess(ctx context.Context, credential, hostname string, operation Operation) (string, error) {
	if a.App == nil {
		return "", fmt.Errorf("gateway app is not configured")
	}
	userVault, err := vaultc.NewWithToken(a.App.Cfg.VaultAddr, config.SRERootCA, credential)
	if err != nil {
		return "", err
	}
	info, err := userVault.LookupToken(ctx)
	if err != nil {
		return "", fmt.Errorf("validate operator token: %w", err)
	}
	if info.Identity == "" {
		return "", fmt.Errorf("operator token has no stable identity")
	}
	if authz.HasAdminPolicy(info.Policies, a.App.Cfg.AdminPolicies) {
		return info.Identity, nil
	}
	storeHandle, err := a.App.OpenStore(ctx, app.PurposeInventoryRead)
	if err != nil {
		return "", err
	}
	defer storeHandle.Close()
	commands, err := storeHandle.RBACCommandsForUser(ctx, info.Identity)
	if err != nil {
		return "", fmt.Errorf("read operator access grant: %w", err)
	}
	grant := "node-access"
	if operation == OperationShellSession {
		grant = "node-access-shell"
	}
	if !commands["*"] && !commands[grant] {
		return "", fmt.Errorf("operator lacks %s grant", grant)
	}
	return info.Identity, nil
}

func (a VCTLAdapters) AuthorizeNode(ctx context.Context, hostname string) error {
	if a.App == nil {
		return fmt.Errorf("gateway app is not configured")
	}
	st, err := a.App.OpenStore(ctx, app.PurposeInventoryRead)
	if err != nil {
		return err
	}
	defer st.Close()
	// Physical hosts use their inventory hostname. Linux VM agents identify
	// themselves by Nova UUID, so resolve those through the VM inventory as a
	// separate identity namespace instead of treating a compute host agent as
	// authority for its guests.
	if host, hostErr := st.Get(ctx, hostname); hostErr == nil {
		if store.StateOrActive(host.State) != store.StateActive {
			return fmt.Errorf("node is not active")
		}
		return nil
	}
	vms, err := st.Instances(ctx, store.InstanceFilter{InstanceID: hostname, IncludeMissing: true})
	if err != nil {
		return fmt.Errorf("look up VM identity: %w", err)
	}
	if len(vms) == 0 {
		return fmt.Errorf("node does not exist in host or OpenStack VM inventory")
	}
	if len(vms) != 1 {
		return fmt.Errorf("VM identity is ambiguous across %d deployments", len(vms))
	}
	vm := vms[0]
	if vm.MissingSince != nil || vm.Status != "ACTIVE" {
		return fmt.Errorf("VM is not active in OpenStack inventory")
	}
	if vm.ObservedAt.IsZero() || time.Since(vm.ObservedAt) > 3*time.Hour {
		return fmt.Errorf("VM inventory record is stale")
	}
	return nil
}

func (a VCTLAdapters) RecordNodeAccess(ctx context.Context, event AuditEvent) error {
	if a.App == nil {
		return fmt.Errorf("gateway app is not configured")
	}
	st, err := a.App.OpenStore(ctx, app.PurposeNodeAccessAudit)
	if err != nil {
		return err
	}
	defer st.Close()
	phase := "finished"
	if event.Outcome == "started" {
		phase = "started"
	}
	var endedAt *time.Time
	if !event.EndedAt.IsZero() {
		ended := event.EndedAt
		endedAt = &ended
	}
	return st.InsertNodeAccessAudit(ctx, store.NodeAccessAuditEvent{
		RequestID:  event.RequestID,
		Phase:      phase,
		Operator:   event.Operator,
		Hostname:   event.Node,
		TargetKind: event.TargetKind,
		Operation:  string(event.Operation),
		StartedAt:  event.StartedAt,
		EndedAt:    endedAt,
		Outcome:    event.Outcome,
	})
}
