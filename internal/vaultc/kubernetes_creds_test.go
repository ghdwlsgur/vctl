package vaultc

import (
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

func TestParseK8sCredsReadsTheEngineShape(t *testing.T) {
	sec := &vault.Secret{LeaseID: "kubernetes/x/creds/viewer/abc", LeaseDuration: 3600, Data: map[string]any{
		"service_account_token": "eyJ-test-token-not-real", "service_account_name": "v-someone-viewer-a1b2c3", "service_account_namespace": "vctl-access",
	}}
	got, err := parseK8sCreds(sec)
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "eyJ-test-token-not-real" || got.ServiceAccount != "v-someone-viewer-a1b2c3" || got.Namespace != "vctl-access" || got.TTL != time.Hour || got.LeaseID == "" {
		t.Errorf("parsed %+v", got)
	}
	for name, bad := range map[string]*vault.Secret{
		"nil":      nil,
		"no data":  {},
		"no token": {Data: map[string]any{"service_account_name": "x"}},
	} {
		if _, err := parseK8sCreds(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
