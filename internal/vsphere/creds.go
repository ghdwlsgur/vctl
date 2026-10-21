package vsphere

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// KV is the one Vault call the poller needs; *vaultc.Client satisfies it.
type KV interface {
	ReadKV(ctx context.Context, path string) (map[string]string, error)
}

// Creds reads an ESXi host's login from Vault, at use time.
//
// One secret per host, named after the inventory hostname rather than the
// address: a host that is re-addressed keeps its secret, and the poller's
// policy can be scoped to the vctl-esxi- prefix alone.
type Creds struct {
	KV     KV
	Prefix string // kv/teams/sre
}

// Key is the secret name under Prefix for hostname.
func Key(hostname string) string { return "vctl-esxi-" + hostname }

// Path is the full KV path the poller reads for hostname.
func (c Creds) Path(hostname string) string {
	return strings.TrimRight(c.Prefix, "/") + "/" + Key(hostname)
}

// Target builds the login for hostname. addr is the inventory address, used
// when the secret does not name an endpoint of its own.
//
// Fields: username and password (required), url (optional, overrides addr),
// thumbprint (optional, pins the certificate).
func (c Creds) Target(ctx context.Context, hostname, addr string, insecure bool) (Target, error) {
	path := c.Path(hostname)
	m, err := c.KV.ReadKV(ctx, path)
	if err != nil {
		return Target{}, fmt.Errorf("read %s: %w", path, err)
	}
	t := Target{
		URL:        strings.TrimSpace(m["url"]),
		Username:   strings.TrimSpace(m["username"]),
		Password:   m["password"],
		Thumbprint: strings.TrimSpace(m["thumbprint"]),
		Insecure:   insecure,
	}
	if t.Username == "" || t.Password == "" {
		return Target{}, fmt.Errorf("%s: username and password are required", path)
	}
	if t.URL == "" {
		if addr == "" {
			return Target{}, fmt.Errorf("%s: no url, and the inventory has no address for %s", path, hostname)
		}
		t.URL = "https://" + net.JoinHostPort(strings.Split(addr, "/")[0], "443") + "/sdk"
	}
	return t, nil
}
