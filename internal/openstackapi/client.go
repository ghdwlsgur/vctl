// Package openstackapi talks to an OpenStack control plane, well enough to ask
// it which hosts it owns.
//
// This is deliberately not gophercloud. Two calls are needed — authenticate,
// then list hypervisors — and both are a single JSON request. Pulling in a full
// SDK for that would add a large dependency surface to a binary that runs as
// root on every host in the fleet, to save about eighty lines.
package openstackapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Credentials authenticate against one deployment's Keystone.
type Credentials struct {
	AuthURL     string
	Username    string
	Password    string
	ProjectName string
	UserDomain  string
	ProjectDom  string
}

// Client is a session against one deployment.
type Client struct {
	http     *http.Client
	authURL  string
	token    string
	computes []endpoint
}

type endpoint struct {
	iface string
	url   string
}

// New authenticates and returns a session.
//
// insecure skips certificate verification. Several deployments here front
// Keystone with a self-signed certificate on an IP, which no CA can be made to
// vouch for; the caller decides, per deployment, and it is not the default.
func New(ctx context.Context, c Credentials, insecure bool, timeout time.Duration) (*Client, error) {
	if c.AuthURL == "" || c.Username == "" || c.Password == "" {
		return nil, fmt.Errorf("auth url, username and password are all required")
	}
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- caller's explicit per-deployment choice
	}
	cl := &Client{
		http:    &http.Client{Timeout: timeout, Transport: tr},
		authURL: strings.TrimRight(c.AuthURL, "/"),
	}
	if err := cl.authenticate(ctx, c); err != nil {
		return nil, err
	}
	return cl, nil
}

// authenticate performs a Keystone v3 password grant and keeps the token and
// the service catalog.
func (c *Client) authenticate(ctx context.Context, cr Credentials) error {
	body := map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"password"},
				"password": map[string]any{
					"user": map[string]any{
						"name":     cr.Username,
						"password": cr.Password,
						"domain":   map[string]string{"name": orDefault(cr.UserDomain, "Default")},
					},
				},
			},
			"scope": map[string]any{
				"project": map[string]any{
					"name":   orDefault(cr.ProjectName, "admin"),
					"domain": map[string]string{"name": orDefault(cr.ProjectDom, "Default")},
				},
			},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokensURL(), bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		// The body is deliberately not included. Keystone echoes parts of the
		// request on some errors, and this request carries a password.
		return fmt.Errorf("keystone authentication failed: %s", resp.Status)
	}
	c.token = resp.Header.Get("X-Subject-Token")
	if c.token == "" {
		return fmt.Errorf("keystone returned no token")
	}
	var out struct {
		Token struct {
			Catalog []struct {
				Type      string `json:"type"`
				Endpoints []struct {
					Interface string `json:"interface"`
					URL       string `json:"url"`
				} `json:"endpoints"`
			} `json:"catalog"`
		} `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return err
	}
	for _, s := range out.Token.Catalog {
		if s.Type != "compute" {
			continue
		}
		for _, e := range s.Endpoints {
			c.computes = append(c.computes, endpoint{iface: e.Interface, url: strings.TrimRight(e.URL, "/")})
		}
	}
	if len(c.computes) == 0 {
		return fmt.Errorf("no compute endpoint in the service catalog")
	}
	return nil
}

// tokensURL builds the v3 token endpoint whether or not auth_url already
// carries a version. Deployments here write it both ways.
func (c *Client) tokensURL() string {
	if strings.Contains(c.authURL, "/v3") {
		return c.authURL + "/auth/tokens"
	}
	return c.authURL + "/v3/auth/tokens"
}

// Hypervisor is one compute host as the control plane knows it.
type Hypervisor struct {
	// Hostname is what nova calls the host. It is not always the inventory
	// name, which is why the caller matches rather than assumes.
	Hostname string `json:"hypervisor_hostname"`
	State    string `json:"state"`
	Status   string `json:"status"`
}

// Hypervisors asks nova which compute hosts this deployment owns.
//
// This is the whole point of the reconciler: it is the only source that can say
// a host belongs to a deployment rather than merely pointing at its Keystone.
func (c *Client) Hypervisors(ctx context.Context) ([]Hypervisor, error) {
	var last error
	// Internal first: the reconciler runs inside the cluster, and the public
	// endpoint of these deployments is often not routable from there.
	for _, e := range preferInternal(c.computes) {
		out, err := c.hypervisorsFrom(ctx, e.url)
		if err != nil {
			last = err
			continue
		}
		return out, nil
	}
	return nil, last
}

func (c *Client) hypervisorsFrom(ctx context.Context, base string) ([]Hypervisor, error) {
	u := base + "/os-hypervisors/detail"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", hostOf(u), resp.Status)
	}
	var out struct {
		Hypervisors []Hypervisor `json:"hypervisors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out); err != nil {
		return nil, err
	}
	return out.Hypervisors, nil
}

func preferInternal(eps []endpoint) []endpoint {
	order := map[string]int{"internal": 0, "admin": 1, "public": 2}
	out := make([]endpoint, len(eps))
	copy(out, eps)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && order[out[j].iface] < order[out[j-1].iface]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// hostOf keeps an error message to the endpoint's host. A full URL from a
// service catalog can carry a project id, and errors end up in the database.
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return "compute endpoint"
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
