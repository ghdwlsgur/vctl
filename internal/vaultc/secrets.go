package vaultc

import (
	"context"
	"fmt"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// readPath/writePath wrap Logical().Read/Write with uniform handling: a
// path-prefixed transport error and an "empty response" guard, so callers skip
// the repeated nil/Data checks. The returned secret has non-nil Data.
func (c *Client) readPath(ctx context.Context, path string) (*vault.Secret, error) {
	sec, err := c.api.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("%s: empty response", path)
	}
	return sec, nil
}

func (c *Client) writePath(ctx context.Context, path string, payload map[string]interface{}) (*vault.Secret, error) {
	sec, err := c.api.Logical().WriteWithContext(ctx, path, payload)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if sec == nil || sec.Data == nil {
		return nil, fmt.Errorf("%s: empty response", path)
	}
	return sec, nil
}

// reqString extracts a required non-empty string field, erroring with the path.
func reqString(sec *vault.Secret, path, key string) (string, error) {
	v, _ := sec.Data[key].(string)
	if v == "" {
		return "", fmt.Errorf("%s: missing %s", path, key)
	}
	return v, nil
}

// SignSSH signs a public key through ssh/sign/<role> and returns an OpenSSH cert.
// The private key remains client-side and is never sent to Vault.
func (c *Client) SignSSH(ctx context.Context, role, publicKey string, principals []string, ttl string, extensions []string) (string, error) {
	payload := map[string]interface{}{
		"public_key":       publicKey,
		"valid_principals": strings.Join(principals, ","),
		"ttl":              ttl,
	}
	if len(extensions) > 0 {
		ext := make(map[string]interface{}, len(extensions))
		for _, name := range extensions {
			ext[name] = ""
		}
		payload["extensions"] = ext
	}
	path := "ssh/sign/" + role
	sec, err := c.writePath(ctx, path, payload)
	if err != nil {
		return "", err
	}
	return reqString(sec, path, "signed_key")
}

// SSHCAPublicKey returns the Vault SSH CA public key (ssh/config/ca). Hosts trust
// this key via TrustedUserCAKeys so they accept vctl's signed certificates.
func (c *Client) SSHCAPublicKey(ctx context.Context) (string, error) {
	sec, err := c.readPath(ctx, "ssh/config/ca")
	if err != nil {
		return "", err
	}
	pub, err := reqString(sec, "ssh/config/ca", "public_key")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(pub), nil
}

// DBCreds requests short-lived Postgres credentials from database/creds/<role>.
func (c *Client) DBCreds(ctx context.Context, role string) (user, pass string, ttl time.Duration, err error) {
	path := "database/creds/" + role
	sec, err := c.readPath(ctx, path)
	if err != nil {
		return "", "", 0, err
	}
	if user, err = reqString(sec, path, "username"); err != nil {
		return "", "", 0, err
	}
	if pass, err = reqString(sec, path, "password"); err != nil {
		return "", "", 0, err
	}
	return user, pass, time.Duration(sec.LeaseDuration) * time.Second, nil
}

// AppRoleRoleID reads the role_id for an approle role (not a secret).
func (c *Client) AppRoleRoleID(ctx context.Context, mount, role string) (string, error) {
	p := fmt.Sprintf("auth/%s/role/%s/role-id", mount, role)
	sec, err := c.readPath(ctx, p)
	if err != nil {
		return "", err
	}
	return reqString(sec, p, "role_id")
}

// GenerateSecretID issues a fresh secret_id for an approle role.
func (c *Client) GenerateSecretID(ctx context.Context, mount, role string) (string, error) {
	p := fmt.Sprintf("auth/%s/role/%s/secret-id", mount, role)
	sec, err := c.writePath(ctx, p, nil)
	if err != nil {
		return "", err
	}
	return reqString(sec, p, "secret_id")
}
