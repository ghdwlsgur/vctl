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
	config, err := renderVMAgentCloudConfig("https://node-access.sre.local", instanceID, "placeholder")
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
