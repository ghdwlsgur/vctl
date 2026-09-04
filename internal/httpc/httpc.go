// Package httpc is the HTTP plumbing the hand-rolled API clients share.
// kubeapi, gitlabapi and openstackapi each talk to one REST API over net/http
// rather than through a vendored SDK, and the parts that are the same for all
// three live here: a TLS-aware client, and a request whose answer is read once,
// bounded, and handed back for the caller to judge.
//
// What is not here is deliberate. Each API has its own idea of an auth header,
// of what a conflict looks like (a 409 to one, a 400 with a sentence to
// another), and of how much of an error body an operator should see. Those
// stay with the API that knows.
package httpc

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNoUsableCA is NewClient's refusal when a CA bundle was given and none of
// it parses. It is a sentinel so a caller can name its own CA in the message.
var ErrNoUsableCA = errors.New("no usable certificate in the CA bundle")

// TLS is what a client needs to know to trust the far side.
type TLS struct {
	// CAPEM, when set, is the only trust: the system roots are not consulted.
	CAPEM []byte
	// ServerName overrides the name verification expects — for an API server
	// reached through a load balancer whose address is not in the SANs.
	ServerName string
	// Insecure skips verification. A caller's explicit, per-endpoint choice
	// (a self-signed OpenStack control plane); never a default.
	Insecure bool
}

// NewClient builds an *http.Client with timeout and t. An unusable CAPEM is an
// error rather than a silent fall back to the system roots: a client that was
// told which CA to trust and trusts something else can be redirected.
//
// The transport is a bare http.Transport on purpose — no proxy from the
// environment — because these clients reach fleet-internal endpoints whose
// path must not depend on the workstation's HTTP_PROXY.
func NewClient(timeout time.Duration, t TLS) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.ServerName}
	if len(t.CAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(t.CAPEM) {
			return nil, ErrNoUsableCA
		}
		cfg.RootCAs = pool
	}
	if t.Insecure {
		cfg.InsecureSkipVerify = true // #nosec G402 -- caller's explicit per-endpoint choice
	}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}

// Response is one answer with its body already read.
type Response struct {
	Status     int
	StatusText string // as the server sent it, e.g. "403 Forbidden"
	Header     http.Header
	Body       []byte
}

// OK is any 2xx.
func (r Response) OK() bool { return r.Status >= 200 && r.Status < 300 }

// JSON decodes the body into v.
func (r Response) JSON(v any) error { return json.Unmarshal(r.Body, v) }

// Do sends req and reads at most maxBody bytes of the answer. It judges
// nothing about the status — the caller decides what a conflict or a failure
// is for its API. The body is read fully and once, so every path (success,
// error, a message for the operator) works from the same bytes and the
// connection goes back to the pool.
func Do(c *http.Client, req *http.Request, maxBody int64) (Response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return Response{}, err
	}
	return Response{Status: resp.StatusCode, StatusText: resp.Status, Header: resp.Header, Body: body}, nil
}

// Snippet is a body cut down to what belongs in an error message: trimmed,
// and no longer than n bytes — a proxy's HTML error page must not flood a
// terminal.
func Snippet(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}
