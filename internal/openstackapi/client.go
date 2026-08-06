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
	// identities are the Keystone endpoints from the catalog, used to turn
	// project ids into the names people actually call them by.
	identities []endpoint
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
		for _, e := range s.Endpoints {
			ep := endpoint{iface: e.Interface, url: strings.TrimRight(e.URL, "/")}
			switch s.Type {
			case "compute":
				c.computes = append(c.computes, ep)
			case "identity":
				c.identities = append(c.identities, ep)
			}
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

// HostList is what the control plane said, and how completely it said it.
//
// Complete matters more than the names do. A reconcile that treats a partial
// answer as the whole truth demotes confirmed hosts to local-only on the
// strength of an endpoint that happened to be refused — the inventory then
// reports a change in the deployment when what changed was one API call.
type HostList struct {
	Hosts []string `json:"hosts"`

	// Complete is true only when both endpoints answered. Callers that write
	// membership must refuse to demote anything when it is false.
	Complete bool `json:"complete"`

	HypervisorError string `json:"hypervisor_error,omitempty"`
	ServiceError    string `json:"service_error,omitempty"`
}

// Hosts asks nova which machines this deployment owns, compute and control
// plane alike.
//
// os-hypervisors alone was the first implementation and it left every
// controller permanently local-only: a controller runs nova-api and
// nova-conductor, not a hypervisor, so it is simply not in that list. The farm
// then confirmed its compute nodes and disowned the machine running its own
// Keystone, which reads as a broken inventory rather than as the API's shape.
//
// os-services carries every nova service and the host it runs on, which covers
// the control plane. Both are asked because the two lists genuinely differ: a
// compute node whose nova-compute is down drops out of os-services but stays a
// hypervisor.
func (c *Client) Hosts(ctx context.Context) (HostList, error) {
	seen := map[string]bool{}
	var out HostList
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out.Hosts = append(out.Hosts, name)
	}
	hs, hErr := c.Hypervisors(ctx)
	for _, h := range hs {
		add(h.Hostname)
	}
	ss, sErr := c.Services(ctx)
	for _, s := range ss {
		add(s.Host)
	}
	if hErr != nil {
		out.HypervisorError = hErr.Error()
	}
	if sErr != nil {
		out.ServiceError = sErr.Error()
	}
	out.Complete = hErr == nil && sErr == nil

	// Only when neither answered is there nothing to report at all. One of the
	// two failing still yields a usable list — some deployments restrict
	// os-services by policy — but it is explicitly marked incomplete, because
	// os-services missing hides controllers and os-hypervisors missing hides
	// compute nodes whose nova-compute is down.
	if hErr != nil && sErr != nil {
		return out, hErr
	}
	return out, nil
}

// Service is one nova service as the control plane knows it.
type Service struct {
	Host   string `json:"host"`
	Binary string `json:"binary"`
	State  string `json:"state"`
	Status string `json:"status"`
}

// Services lists nova's services, which is how a controller becomes visible.
func (c *Client) Services(ctx context.Context) ([]Service, error) {
	var last error
	for _, e := range preferInternal(c.computes) {
		var out struct {
			Services []Service `json:"services"`
		}
		if err := c.getJSON(ctx, e.url+"/os-services", &out); err != nil {
			last = err
			continue
		}
		return out.Services, nil
	}
	return nil, last
}

// Hypervisors asks nova which compute hosts this deployment owns.
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
	var out struct {
		Hypervisors []Hypervisor `json:"hypervisors"`
	}
	if err := c.getJSON(ctx, base+"/os-hypervisors/detail", &out); err != nil {
		return nil, err
	}
	return out.Hypervisors, nil
}

// getJSON performs one authenticated read.
func (c *Client) getJSON(ctx context.Context, u string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// The host only. A service catalog URL can carry a project id, and
		// errors end up in the database.
		return fmt.Errorf("%s: %s", hostOf(u), resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(into)
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
