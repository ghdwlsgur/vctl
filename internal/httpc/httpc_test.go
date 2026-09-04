package httpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientRefusesAnUnusableCA(t *testing.T) {
	if _, err := NewClient(time.Second, TLS{CAPEM: []byte("not a certificate")}); err != ErrNoUsableCA {
		t.Fatalf("err = %v, want ErrNoUsableCA — a client told which CA to trust must not fall back to the system roots", err)
	}
	// No bundle at all is the system roots, not an error.
	if _, err := NewClient(time.Second, TLS{}); err != nil {
		t.Fatal(err)
	}
}

func TestDoReadsOnceAndBoundsTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Marker", "here")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := Do(srv.Client(), req, 10)
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK() || resp.Status != http.StatusTeapot || !strings.HasPrefix(resp.StatusText, "418") {
		t.Errorf("status = %d %q, OK=%v", resp.Status, resp.StatusText, resp.OK())
	}
	if len(resp.Body) != 10 {
		t.Errorf("body = %d bytes, want the 10-byte bound", len(resp.Body))
	}
	if resp.Header.Get("X-Marker") != "here" {
		t.Error("headers were not carried")
	}
}

func TestSnippetTrimsAndCuts(t *testing.T) {
	if got := Snippet([]byte("  short \n"), 300); got != "short" {
		t.Errorf("Snippet = %q", got)
	}
	if got := Snippet([]byte(strings.Repeat("a", 50)), 8); got != "aaaaaaaa…" {
		t.Errorf("Snippet = %q, want 8 bytes and an ellipsis", got)
	}
}
