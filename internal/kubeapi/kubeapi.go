// Package kubeapi is the sliver of the Kubernetes API vctl uses: reading and
// patching one ConfigMap. Hand-rolled over net/http the way internal/
// openstackapi is, because client-go is a dependency tree the size of the
// rest of the binary — for two REST calls against one resource.
//
// Credentials are a ServiceAccount token and the cluster CA, read from Vault
// at use time by the caller. The token's Role is the authority on what this
// client may touch; nothing here widens it.
package kubeapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrConflict is the optimistic-concurrency refusal: the object moved between
// the read and the write. The caller re-reads and reapplies — silently
// clobbering a concurrent edit is how a DNS record vanishes with no history.
var ErrConflict = errors.New("the object changed since it was read")

// Client is a session against one cluster, as one ServiceAccount.
type Client struct {
	base  string
	token string
	http  *http.Client
}

// New builds a client for server, trusting caPEM and authenticating with a
// bearer token. The CA is required: this client exists to mutate the fleet's
// DNS, and a write that cannot verify who it is talking to is a write that
// can be redirected.
//
// serverName overrides TLS verification's expected name — the same seam the
// Postgres path calls DBServerName. The fleet fronts its API server with a
// load balancer whose address is not in the serving certificate's SANs;
// kubeconfigs carry tls-server-name for exactly this, and so does the Vault
// secret this client's inputs come from.
func New(server, token string, caPEM []byte, serverName string) (*Client, error) {
	if server == "" || token == "" {
		return nil, fmt.Errorf("kubernetes server and token are both required")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no usable certificate in the cluster CA")
	}
	return &Client{
		base:  strings.TrimRight(server, "/"),
		token: token,
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12,
			}},
		},
	}, nil
}

// ConfigMap is the part of the object vctl reads: the data, the annotations,
// and the version the next write must name.
type ConfigMap struct {
	ResourceVersion string
	Data            map[string]string
	Annotations     map[string]string
}

func (c *Client) cmURL(namespace, name string) string {
	return fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps/%s", c.base, namespace, name)
}

// GetConfigMap reads one ConfigMap.
func (c *Client) GetConfigMap(ctx context.Context, namespace, name string) (*ConfigMap, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cmURL(namespace, name), nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Metadata struct {
			ResourceVersion string            `json:"resourceVersion"`
			Annotations     map[string]string `json:"annotations"`
		} `json:"metadata"`
		Data map[string]string `json:"data"`
	}
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return &ConfigMap{
		ResourceVersion: out.Metadata.ResourceVersion,
		Data:            out.Data,
		Annotations:     out.Metadata.Annotations,
	}, nil
}

// PatchConfigMapData replaces data keys (and merges annotations) with a JSON
// merge patch, preconditioned on resourceVersion: naming the version in the
// patch makes the API server refuse (409 → ErrConflict) when the object has
// moved since the caller read it.
func (c *Client) PatchConfigMapData(ctx context.Context, namespace, name, resourceVersion string,
	data map[string]string, annotations map[string]string) error {
	body := map[string]any{
		"metadata": map[string]any{
			"resourceVersion": resourceVersion,
			"annotations":     annotations,
		},
		"data": data,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.cmURL(namespace, name), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/merge-patch+json")
	return c.do(req, nil)
}

func (c *Client) do(req *http.Request, into any) error {
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("%s: %w", req.URL.Path, ErrConflict)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The API server's status message names the reason (forbidden, not
		// found); the operator gets it verbatim, bounded so a proxy's error
		// page cannot flood a terminal.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s: %s: %s", req.URL.Path, resp.Status, statusMessage(msg))
	}
	if into == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(into)
}

// statusMessage pulls the human sentence out of a k8s Status body, falling
// back to the raw bytes when it is not one.
func statusMessage(body []byte) string {
	var st struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &st) == nil && st.Message != "" {
		return st.Message
	}
	return strings.TrimSpace(string(body))
}
