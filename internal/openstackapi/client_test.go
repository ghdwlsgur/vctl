package openstackapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// fakeCloud is a Keystone + nova stand-in, so the client can be exercised
// against shaped responses instead of a live deployment.
type fakeCloud struct {
	hypervisors []string
	services    []string
	// fail names endpoints that should return 403, for the partial-answer case.
	fail map[string]bool
}

func (f *fakeCloud) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/v3/auth/tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Subject-Token", "fake-token")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": map[string]any{
			"catalog": []any{map[string]any{
				"type":      "compute",
				"endpoints": []any{map[string]string{"interface": "internal", "url": srv.URL + "/v2.1"}},
			}},
		}})
	})
	mux.HandleFunc("/v2.1/os-hypervisors/detail", func(w http.ResponseWriter, _ *http.Request) {
		if f.fail["hypervisors"] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		hs := make([]map[string]string, 0, len(f.hypervisors))
		for _, h := range f.hypervisors {
			hs = append(hs, map[string]string{"hypervisor_hostname": h})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"hypervisors": hs})
	})
	mux.HandleFunc("/v2.1/os-services", func(w http.ResponseWriter, _ *http.Request) {
		if f.fail["services"] {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ss := make([]map[string]string, 0, len(f.services))
		for _, h := range f.services {
			ss = append(ss, map[string]string{"host": h, "binary": "nova-conductor"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"services": ss})
	})
	return srv
}

func (f *fakeCloud) client(t *testing.T) *Client {
	t.Helper()
	srv := f.start(t)
	c, err := New(context.Background(), Credentials{
		AuthURL: srv.URL, Username: "u", Password: "p",
	}, false, 10*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// A controller runs nova-api and nova-conductor, not a hypervisor, so it is not
// in os-hypervisors at all. Asking only for hypervisors left every controller
// permanently local-only: the farm confirmed its compute nodes and disowned the
// machine running its own Keystone.
func TestHostsIncludesTheControlPlane(t *testing.T) {
	f := &fakeCloud{
		hypervisors: []string{"compute-01", "compute-02"},
		services:    []string{"controller-01", "compute-01"},
	}
	got, err := f.client(t).Hosts(context.Background())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}

	for _, want := range []string{"compute-01", "compute-02", "controller-01"} {
		if !slices.Contains(got, want) {
			t.Errorf("hosts = %v, missing %s", got, want)
		}
	}
	// compute-01 is in both lists and must appear once, or the caller counts it
	// twice.
	var n int
	for _, h := range got {
		if h == "compute-01" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("compute-01 appears %d times, want 1", n)
	}
}

// The two lists genuinely differ: a compute node whose nova-compute is down
// drops out of os-services but stays a hypervisor. Losing it would mark a host
// control-only that the deployment still owns.
func TestHostsKeepsAHypervisorMissingFromServices(t *testing.T) {
	f := &fakeCloud{hypervisors: []string{"compute-down"}, services: []string{"controller-01"}}

	got, err := f.client(t).Hosts(context.Background())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if !slices.Contains(got, "compute-down") {
		t.Errorf("hosts = %v, lost the hypervisor that has no live service", got)
	}
}

// Some deployments restrict os-services by policy. One call failing is
// survivable; reporting the partial list as complete is not, so the other
// call's answer still stands.
func TestHostsSurvivesOneEndpointBeingRefused(t *testing.T) {
	f := &fakeCloud{
		hypervisors: []string{"compute-01"},
		fail:        map[string]bool{"services": true},
	}
	got, err := f.client(t).Hosts(context.Background())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if !slices.Contains(got, "compute-01") {
		t.Errorf("hosts = %v, want the endpoint that did answer", got)
	}
}

// Neither answering is a failure to look, and must not read as an empty
// deployment — that would mark every host control-only.
func TestHostsFailsWhenNeitherEndpointAnswers(t *testing.T) {
	f := &fakeCloud{fail: map[string]bool{"services": true, "hypervisors": true}}

	if _, err := f.client(t).Hosts(context.Background()); err == nil {
		t.Fatal("both endpoints refused and the deployment was reported as empty")
	}
}
