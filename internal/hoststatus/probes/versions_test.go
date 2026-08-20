package probes

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// serveVersion stands up a unix socket that answers /version the way an engine
// does, so the parsing is exercised against the wire shape rather than a struct.
func serveVersion(t *testing.T, body any, status int) string {
	t.Helper()
	// Not t.TempDir(): a unix socket address is capped near 104 bytes on darwin
	// and t.TempDir() spells the test name into the path, which makes the longer
	// names here fail to bind.
	dir, err := os.MkdirTemp("", "eng")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")

	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close(); l.Close() })
	return sock
}

// Podman spells the runtime "OCI Runtime (crun)".
func TestEngineVersionsReadsPodman(t *testing.T) {
	sock := serveVersion(t, map[string]any{
		"Version": "5.6.0",
		"Components": []map[string]string{
			{"Name": "Podman Engine", "Version": "5.6.0"},
			{"Name": "Conmon", "Version": "2.1.12"},
			{"Name": "OCI Runtime (crun)", "Version": "1.23.1"},
		},
	}, http.StatusOK)

	got := engineVersions(context.Background(), sock)
	for k, want := range map[string]string{
		"engine": "5.6.0", "oci-runtime": "1.23.1", "oci-runtime-name": "OCI Runtime (crun)",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}

// Docker reports runc as a component named for itself. The role key has to be
// the same either way or a mixed fleet cannot be compared.
func TestEngineVersionsReadsDocker(t *testing.T) {
	sock := serveVersion(t, map[string]any{
		"Version": "27.3.1",
		"Components": []map[string]string{
			{"Name": "Engine", "Version": "27.3.1"},
			{"Name": "runc", "Version": "1.1.14"},
		},
	}, http.StatusOK)

	got := engineVersions(context.Background(), sock)
	if got["engine"] != "27.3.1" {
		t.Errorf("engine = %q, want 27.3.1", got["engine"])
	}
	if got["oci-runtime"] != "1.1.14" {
		t.Errorf("oci-runtime = %q, want 1.1.14 — the role key must not depend on the implementation", got["oci-runtime"])
	}
}

// A socket that answers the listing but not this is a version we do not learn,
// not a probe that failed. The capability is built from the listing.
func TestEngineVersionsIsSilentWhenItCannotAsk(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   any
		status int
	}{
		{"error status", nil, http.StatusInternalServerError},
		{"not json", "{{{", http.StatusOK},
		{"nothing useful", map[string]any{"Arch": "amd64"}, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := serveVersion(t, tc.body, tc.status)
			if got := engineVersions(context.Background(), sock); got != nil {
				t.Errorf("got %v, want nil", got)
			}
		})
	}
	t.Run("no socket at all", func(t *testing.T) {
		if got := engineVersions(context.Background(), "/nonexistent/sock"); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})
}

// The probe carries what the socket said into the capability's components,
// which is where a fleet-wide comparison can reach it.
func TestOpenStackProbeRecordsTheRuntimeVersion(t *testing.T) {
	// A socket file under a fake root, the way the other probe tests do it —
	// exists() stats p.path(), so presence is a real file rather than a stub.
	root := t.TempDir()
	sock := containerSockets[0].path
	if err := os.MkdirAll(filepath.Dir(root+sock), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(root+sock, nil, 0o600); err != nil {
		t.Fatalf("write socket: %v", err)
	}
	p := &OpenStack{
		root: root,
		versionSocket: func(context.Context, string) map[string]string {
			return map[string]string{"engine": "5.6.0", "oci-runtime": "1.23.1", "oci-runtime-name": "OCI Runtime (crun)"}
		},
		listSocket: func(context.Context, string) (map[string]containerInfo, error) {
			return map[string]containerInfo{"nova_compute": {State: "running"}}, nil
		},
	}
	res := p.Collect(context.Background())
	if c, ok := res.Components["oci-runtime"]; !ok || c.Version != "1.23.1" {
		t.Errorf("oci-runtime component = %+v, want version 1.23.1", res.Components["oci-runtime"])
	}
	if c, ok := res.Components[containerSockets[0].engine]; !ok || c.Version != "5.6.0" {
		t.Errorf("%s component = %+v, want version 5.6.0", containerSockets[0].engine, res.Components[containerSockets[0].engine])
	}
	if got := res.Details["oci_runtime"]; got != "OCI Runtime (crun)" {
		t.Errorf("oci_runtime detail = %q; crun and runc are not interchangeable and their numbers are unrelated", got)
	}
}
