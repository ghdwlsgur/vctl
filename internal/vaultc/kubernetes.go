package vaultc

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// DefaultServiceAccountTokenPath is where the kubelet projects a pod's
// ServiceAccount token. Every pod gets one without asking for it.
const DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // a path, not a credential

// LoginKubernetes exchanges a pod's ServiceAccount token for a Vault token.
//
// This is the auth method for anything vctl runs inside the cluster — the
// migration Job being the first. The alternative was an AppRole, which means a
// secret_id stored in a Kubernetes Secret and rotated by somebody. This fleet
// has already been bitten by exactly that: a 30-day secret_id expired, nothing
// reported it, and 122 hosts stopped sending status for a day (see the comment
// on approles.tf in vault-iac). A ServiceAccount token is projected and rotated
// by the kubelet, so there is no secret to place and none to forget.
//
// The JWT is read at call time rather than at startup. Projected tokens are
// refreshed in place, so a long-running process that cached the file contents
// would re-authenticate with an expired assertion.
func (c *Client) LoginKubernetes(ctx context.Context, mount, role, jwt string) error {
	if mount == "" {
		mount = "kubernetes"
	}
	if role == "" {
		return fmt.Errorf("kubernetes: role is empty")
	}
	if strings.TrimSpace(jwt) == "" {
		return fmt.Errorf("kubernetes: service account token is empty")
	}
	sec, err := c.api.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", map[string]any{
		"role": role,
		"jwt":  strings.TrimSpace(jwt),
	})
	if err != nil {
		return fmt.Errorf("kubernetes login failed (role %q): %w", role, err)
	}
	return c.applyAuth(sec)
}

// ReadServiceAccountToken reads the projected token, reporting a missing file
// as "not running in a pod" rather than as a read error — that distinction is
// what lets a caller fall back to another auth method instead of failing.
func ReadServiceAccountToken(path string) (string, bool, error) {
	if path == "" {
		path = DefaultServiceAccountTokenPath
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read service account token %s: %w", path, err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", false, fmt.Errorf("service account token %s is empty", path)
	}
	return tok, true, nil
}
