package gitlabapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, "glpat-test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetFileDecodesAndCarriesTheCommit(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "glpat-test" {
			t.Error("no token on the request")
		}
		// The project path arrives URL-encoded — GitLab addresses projects by
		// escaped full path, and a slash left bare 404s.
		if r.URL.EscapedPath() != "/api/v4/projects/sre%2Fdevtools%2Fcoredns/repository/files/configmap-hosts.yaml" {
			t.Errorf("path = %s", r.URL.EscapedPath())
		}
		if r.URL.Query().Get("ref") != "main" {
			t.Errorf("ref = %s", r.URL.Query().Get("ref"))
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"content":        base64.StdEncoding.EncodeToString([]byte("data: x\n")),
			"encoding":       "base64",
			"last_commit_id": "abc123",
		})
	})
	f, err := c.GetFile(context.Background(), "sre/devtools/coredns", "configmap-hosts.yaml", "main")
	if err != nil {
		t.Fatal(err)
	}
	if f.Content != "data: x\n" || f.LastCommitID != "abc123" {
		t.Errorf("file = %+v", f)
	}
}

// GitLab answers a stale last_commit_id with a 400 and a sentence, not a 409.
// Both are the same race, and the caller retries on ErrConflict alone — so
// the sentence has to be recognised.
func TestUpdateFileSurfacesTheStaleCommitAsConflict(t *testing.T) {
	stale := false
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var got map[string]string
		_ = json.Unmarshal(body, &got)
		if got["last_commit_id"] != "abc123" || got["branch"] != "main" {
			t.Errorf("commit body = %v", got)
		}
		if stale {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"You are attempting to update a file that has changed since you started editing it."}`))
			return
		}
		_, _ = w.Write([]byte(`{"file_path":"configmap-hosts.yaml","branch":"main"}`))
	})
	if err := c.UpdateFile(context.Background(), "p", "configmap-hosts.yaml", "main", "data: y\n", "dns: add x", "abc123"); err != nil {
		t.Fatal(err)
	}
	stale = true
	err := c.UpdateFile(context.Background(), "p", "configmap-hosts.yaml", "main", "data: y\n", "dns: add x", "abc123")
	if !errors.Is(err, ErrConflict) {
		t.Errorf("a stale commit surfaced as %v, want ErrConflict", err)
	}
}
