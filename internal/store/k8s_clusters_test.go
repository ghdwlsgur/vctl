package store

import (
	"context"
	"errors"
	"testing"
)

// Integration — needs VCTL_TEST_DSN.
func TestK8sClustersRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	c := K8sCluster{
		Name: "test-core", Site: "site-a", APIServer: "https://198.51.100.10:6443",
		TLSServerName: "198.51.100.11", CAPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		Reach: "tunnel", TokenSource: "vault:kubernetes/test-core", Note: "fixture", UpdatedBy: "tester",
	}
	if err := st.K8sClusterUpsert(ctx, c); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.K8sClusterDelete(ctx, "test-core") })

	got, err := st.K8sCluster(ctx, "test-core")
	if err != nil {
		t.Fatal(err)
	}
	if got.APIServer != c.APIServer || got.CAPEM != c.CAPEM || got.Reach != "tunnel" || got.TokenSource != c.TokenSource || got.UpdatedBy != "tester" {
		t.Errorf("read back %+v", got)
	}
	kind, ref := got.TokenSourceKind()
	if kind != "vault" || ref != "kubernetes/test-core" {
		t.Errorf("token source split = %q %q", kind, ref)
	}
	// Upsert updates in place.
	c.Note, c.Reach = "changed", "direct"
	if err := st.K8sClusterUpsert(ctx, c); err != nil {
		t.Fatal(err)
	}
	all, err := st.K8sClusters(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, x := range all {
		if x.Name == "test-core" {
			n++
			if x.Note != "changed" || x.Reach != "direct" {
				t.Errorf("update lost: %+v", x)
			}
		}
	}
	if n != 1 {
		t.Errorf("cluster listed %d times", n)
	}
	if err := st.K8sClusterDelete(ctx, "test-core"); err != nil {
		t.Fatal(err)
	}
	if err := st.K8sClusterDelete(ctx, "test-core"); !errors.Is(err, ErrK8sClusterNotFound) {
		t.Errorf("deleting twice = %v, want not-found", err)
	}
}

func TestValidateK8sClusterNamesTheProblem(t *testing.T) {
	good := K8sCluster{Name: "x", APIServer: "https://198.51.100.10:6443", Reach: "tunnel", TokenSource: "kv:kv/teams/x/k8s/x"}
	if err := ValidateK8sCluster(good); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []K8sCluster{
		{Name: "", APIServer: good.APIServer, Reach: "tunnel", TokenSource: good.TokenSource},
		{Name: "x", APIServer: "http://plain", Reach: "tunnel", TokenSource: good.TokenSource},
		{Name: "x", APIServer: good.APIServer, Reach: "vpn", TokenSource: good.TokenSource},
		{Name: "x", APIServer: good.APIServer, Reach: "direct", TokenSource: "file:/tmp/x"},
		{Name: "x", APIServer: good.APIServer, Reach: "direct", TokenSource: "vault:"},
	} {
		if err := ValidateK8sCluster(bad); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}
