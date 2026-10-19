package nodeaccess

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type novaAuthenticatorFunc func(context.Context, string, string) error

func (f novaAuthenticatorFunc) AuthenticateNova(ctx context.Context, deploymentID, token string) error {
	return f(ctx, deploymentID, token)
}

func TestVendordataReturnsUUIDBoundCloudConfigOnlyForAuthenticatedNova(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	const (
		farmID     = "192.0.2.245:5000"
		projectID  = "project-42"
		instanceID = "123e4567-e89b-12d3-a456-426614174000"
		serviceTok = "nova-service-token"
	)
	called := false
	gateway := &Gateway{
		NovaAuth: novaAuthenticatorFunc(func(_ context.Context, farm, token string) error {
			called = true
			if farm != farmID || token != serviceTok {
				t.Fatal("Nova identity was not validated against the requested farm")
			}
			return nil
		}),
		EnrollmentKey: key,
		GatewayURL:    "https://node-access.sre.local",
	}
	body, err := json.Marshal(map[string]string{
		"project-id":  projectID,
		"instance-id": instanceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/vendordata?farm="+farmID, strings.NewReader(string(body)))
	request.Header.Set("X-Auth-Token", serviceTok)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("vendordata status = %d; body=%s", response.Code, response.Body.String())
	}
	if !called {
		t.Fatal("vendordata was returned without validating Nova's service token")
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q; want no-store", response.Header().Get("Cache-Control"))
	}
	var cloudConfig string
	if err := json.Unmarshal(response.Body.Bytes(), &cloudConfig); err != nil {
		t.Fatalf("decode vendordata response: %v", err)
	}
	if !strings.HasPrefix(cloudConfig, "#cloud-config\n") {
		t.Fatalf("response is not cloud-config: %q", cloudConfig[:min(len(cloudConfig), 80)])
	}
	config, err := renderVMAgentCloudConfig("https://node-access.sre.local", "", instanceID, "placeholder")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "--instance-id "+instanceID) {
		t.Fatal("cloud-init enrollment command is not bound to the Nova instance UUID")
	}
	var token string
	var configDoc vmVendordataCloudConfig
	if err := yaml.Unmarshal([]byte(strings.TrimPrefix(cloudConfig, "#cloud-config\n")), &configDoc); err != nil {
		t.Fatalf("decode cloud-config YAML: %v", err)
	}
	for _, file := range configDoc.WriteFiles {
		if file.Path == "/etc/vctl/session-agent/enrollment-token" {
			token = file.Content
		}
	}
	claims, err := verifyBootstrapToken(key, token, time.Now())
	if err != nil {
		t.Fatalf("verify cloud-init enrollment grant: %v", err)
	}
	if claims.DeploymentID != farmID || claims.ProjectID != projectID || claims.InstanceID != instanceID {
		t.Fatalf("grant claims do not match request: %+v", claims)
	}
}

func TestBootstrapTokenRejectsTamperingAndExpiredClaims(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	claims := bootstrapClaims{
		Version: 1, DeploymentID: "192.0.2.245:5000", ProjectID: "p1",
		InstanceID: "123e4567-e89b-12d3-a456-426614174000",
		IssuedAt:   time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt:  time.Now().Add(-time.Hour).Unix(),
	}
	token, err := signBootstrapToken(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyBootstrapToken(key, token, time.Now()); err == nil {
		t.Fatal("expired bootstrap token was accepted")
	}
	if _, err := verifyBootstrapToken(key, token+"x", time.Now().Add(-3*time.Hour)); err == nil {
		t.Fatal("tampered bootstrap token was accepted")
	}
}

func cloudConfigFiles(t *testing.T, rendered string) map[string]string {
	t.Helper()
	var doc vmVendordataCloudConfig
	if err := yaml.Unmarshal([]byte(strings.TrimPrefix(rendered, "#cloud-config\n")), &doc); err != nil {
		t.Fatalf("decode cloud-config: %v", err)
	}
	files := map[string]string{}
	for _, f := range doc.WriteFiles {
		files[f.Path] = f.Content
	}
	return files
}

// A guest on a tenant network usually resolves through a public resolver
// (8.8.8.8 on the infra farms) and cannot find node-access.sre.local, so the
// download and the enrollment both fail — the 2026-10 pilot had to edit
// /etc/hosts by hand on every VM. With the gateway's address configured, the
// guest pins the name when it does not resolve, before the download and again
// on every agent start, because some images rewrite /etc/hosts at boot.
func TestCloudConfigPinsTheGatewayWhenItsNameDoesNotResolve(t *testing.T) {
	const id = "1f63afab-48ca-45c5-8a84-28469770f3bc"
	rendered, err := renderVMAgentCloudConfig("https://node-access.sre.local", "192.168.201.12", id, "grant")
	if err != nil {
		t.Fatal(err)
	}
	files := cloudConfigFiles(t, rendered)
	pin, ok := files["/usr/local/sbin/vctl-vm-agent-hosts"]
	if !ok {
		t.Fatal("no hosts pin script")
	}
	for _, want := range []string{"getent hosts 'node-access.sre.local'", "192.168.201.12 node-access.sre.local", ">> /etc/hosts"} {
		if !strings.Contains(pin, want) {
			t.Errorf("pin script missing %q:\n%s", want, pin)
		}
	}
	boot := files["/usr/local/sbin/vctl-vm-agent-bootstrap"]
	if i, j := strings.Index(boot, "/usr/local/sbin/vctl-vm-agent-hosts"), strings.Index(boot, "/v1/agent/binary"); i < 0 || j < 0 || i > j {
		t.Error("bootstrap does not pin the gateway before downloading the agent")
	}
	if !strings.Contains(files["/etc/systemd/system/vctl-vm-session-agent.service"], "ExecStartPre=+/usr/local/sbin/vctl-vm-agent-hosts") {
		t.Error("the agent unit does not re-pin the gateway on start")
	}
}

func TestCloudConfigLeavesHostsAloneWithoutAnAddress(t *testing.T) {
	rendered, err := renderVMAgentCloudConfig("https://node-access.sre.local", "", "1f63afab-48ca-45c5-8a84-28469770f3bc", "grant")
	if err != nil {
		t.Fatal(err)
	}
	files := cloudConfigFiles(t, rendered)
	if _, ok := files["/usr/local/sbin/vctl-vm-agent-hosts"]; ok || strings.Contains(rendered, "/etc/hosts") {
		t.Error("touched /etc/hosts with no gateway address configured")
	}
}

// The address lands in a root shell script on every guest.
func TestCloudConfigRefusesAGatewayAddressThatIsNotAnIP(t *testing.T) {
	for _, addr := range []string{"node-access", "192.168.201.12; rm -rf /", "192.168.201.12\n10.0.0.1 evil"} {
		if _, err := renderVMAgentCloudConfig("https://node-access.sre.local", addr, "1f63afab-48ca-45c5-8a84-28469770f3bc", "grant"); err == nil {
			t.Errorf("accepted %q", addr)
		}
	}
}
