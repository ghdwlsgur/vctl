package vaultc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// K8sCreds is a ServiceAccount token minted by Vault's Kubernetes secrets
// engine: short-lived, bound to a role, and — when the engine generates a
// service account per lease — carrying the requester's name into the
// cluster's own audit log.
type K8sCreds struct {
	Token          string
	ServiceAccount string
	Namespace      string
	TTL            time.Duration
	LeaseID        string
}

// KubernetesCreds asks the engine mounted at mount for a token under role,
// with the service account placed in namespace. ttl 0 takes the role's
// default.
func (c *Client) KubernetesCreds(ctx context.Context, mount, role, namespace string, ttl time.Duration) (K8sCreds, error) {
	params := map[string]any{
		"kubernetes_namespace": namespace,
		// The roles are bound to builtin ClusterRoles (view/edit/cluster-admin)
		// and mean the whole cluster. Without this the engine makes a namespaced
		// RoleBinding inside kubernetes_namespace, and a freshly minted viewer
		// sees only vctl-access (found live on v0.8.0: nodes Forbidden).
		"cluster_role_binding": true,
	}
	if ttl > 0 {
		params["ttl"] = int(ttl.Seconds())
	}
	path := strings.TrimSuffix(mount, "/") + "/creds/" + role
	sec, err := c.api.Logical().WriteWithContext(ctx, path, params)
	if err != nil {
		return K8sCreds{}, fmt.Errorf("%s: %w", path, err)
	}
	creds, err := parseK8sCreds(sec)
	if err != nil {
		return K8sCreds{}, fmt.Errorf("%s: %w", path, err)
	}
	return creds, nil
}

func parseK8sCreds(sec *vault.Secret) (K8sCreds, error) {
	if sec == nil || sec.Data == nil {
		return K8sCreds{}, errors.New("the engine returned no credential")
	}
	tok, _ := sec.Data["service_account_token"].(string)
	if tok == "" {
		return K8sCreds{}, errors.New("the engine returned no service_account_token")
	}
	name, _ := sec.Data["service_account_name"].(string)
	ns, _ := sec.Data["service_account_namespace"].(string)
	return K8sCreds{
		Token: tok, ServiceAccount: name, Namespace: ns,
		TTL: time.Duration(sec.LeaseDuration) * time.Second, LeaseID: sec.LeaseID,
	}, nil
}
