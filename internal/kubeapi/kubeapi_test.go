package kubeapi

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	c, err := New(srv.URL, "test-token", ca, "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetConfigMapCarriesTokenAndParses(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("no bearer token on the request")
		}
		if r.URL.Path != "/api/v1/namespaces/dns-system/configmaps/coredns-hosts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"metadata":{"resourceVersion":"41","annotations":{"a":"b"}},"data":{"sre.hosts":"x"}}`))
	})
	cm, err := c.GetConfigMap(context.Background(), "dns-system", "coredns-hosts")
	if err != nil {
		t.Fatal(err)
	}
	if cm.ResourceVersion != "41" || cm.Data["sre.hosts"] != "x" || cm.Annotations["a"] != "b" {
		t.Errorf("parsed %+v", cm)
	}
}

// The patch names the version it read; the API server refusing a moved object
// is the only thing standing between two concurrent edits and a silent
// clobber, so the refusal must surface as ErrConflict and nothing else.
func TestPatchSendsThePreconditionAndSurfacesConflict(t *testing.T) {
	conflict := false
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.Header.Get("Content-Type") != "application/merge-patch+json" {
			t.Errorf("not a merge patch: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		var got struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
			} `json:"metadata"`
		}
		_ = json.Unmarshal(body, &got)
		if got.Metadata.ResourceVersion != "41" {
			t.Errorf("patch names version %q, want 41", got.Metadata.ResourceVersion)
		}
		if conflict {
			w.WriteHeader(http.StatusConflict)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})
	err := c.PatchConfigMapData(context.Background(), "dns-system", "coredns-hosts", "41",
		map[string]string{"sre.hosts": "y"}, map[string]string{"stamp": "now"})
	if err != nil {
		t.Fatal(err)
	}
	conflict = true
	err = c.PatchConfigMapData(context.Background(), "dns-system", "coredns-hosts", "41", nil, nil)
	if !errors.Is(err, ErrConflict) {
		t.Errorf("a 409 surfaced as %v, want ErrConflict", err)
	}
}

// The API server's own sentence reaches the operator — "forbidden" with the
// reason beats a bare status code when the Role is what is wrong.
func TestErrorsCarryTheStatusMessage(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","message":"configmaps \"coredns-hosts\" is forbidden"}`))
	})
	_, err := c.GetConfigMap(context.Background(), "dns-system", "coredns-hosts")
	if err == nil || !strings.Contains(err.Error(), "is forbidden") {
		t.Errorf("err = %v, want the API server's sentence", err)
	}
}
