package vaultc

import (
	"context"
	"fmt"
	"strings"
	"time"
)

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

	sec, err := c.api.Logical().WriteWithContext(ctx, "ssh/sign/"+role, payload)
	if err != nil {
		return "", fmt.Errorf("ssh/sign/%s: %w", role, err)
	}
	if sec == nil || sec.Data == nil {
		return "", fmt.Errorf("ssh/sign/%s: empty response", role)
	}
	signed, ok := sec.Data["signed_key"].(string)
	if !ok || signed == "" {
		return "", fmt.Errorf("ssh/sign/%s: missing signed_key in response", role)
	}
	return signed, nil
}

// DBCreds requests short-lived Postgres credentials from database/creds/<role>.
func (c *Client) DBCreds(ctx context.Context, role string) (user, pass string, ttl time.Duration, err error) {
	sec, err := c.api.Logical().ReadWithContext(ctx, "database/creds/"+role)
	if err != nil {
		return "", "", 0, fmt.Errorf("database/creds/%s: %w", role, err)
	}
	if sec == nil || sec.Data == nil {
		return "", "", 0, fmt.Errorf("database/creds/%s: empty response", role)
	}
	user, _ = sec.Data["username"].(string)
	pass, _ = sec.Data["password"].(string)
	if user == "" || pass == "" {
		return "", "", 0, fmt.Errorf("database/creds/%s: missing username/password", role)
	}
	return user, pass, time.Duration(sec.LeaseDuration) * time.Second, nil
}

// AppRoleRoleID reads the role_id for an approle role (not a secret).
func (c *Client) AppRoleRoleID(ctx context.Context, mount, role string) (string, error) {
	p := fmt.Sprintf("auth/%s/role/%s/role-id", mount, role)
	sec, err := c.api.Logical().ReadWithContext(ctx, p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	if sec == nil || sec.Data == nil {
		return "", fmt.Errorf("%s: empty response", p)
	}
	id, _ := sec.Data["role_id"].(string)
	if id == "" {
		return "", fmt.Errorf("%s: missing role_id", p)
	}
	return id, nil
}

// GenerateSecretID issues a fresh secret_id for an approle role.
func (c *Client) GenerateSecretID(ctx context.Context, mount, role string) (string, error) {
	p := fmt.Sprintf("auth/%s/role/%s/secret-id", mount, role)
	sec, err := c.api.Logical().WriteWithContext(ctx, p, nil)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	if sec == nil || sec.Data == nil {
		return "", fmt.Errorf("%s: empty response", p)
	}
	sid, _ := sec.Data["secret_id"].(string)
	if sid == "" {
		return "", fmt.Errorf("%s: missing secret_id", p)
	}
	return sid, nil
}

// CAPublicKey reads the CA public key from ssh/config/ca.
func (c *Client) CAPublicKey(ctx context.Context) (string, error) {
	sec, err := c.api.Logical().ReadWithContext(ctx, "ssh/config/ca")
	if err != nil {
		return "", fmt.Errorf("ssh/config/ca: %w", err)
	}
	if sec == nil || sec.Data == nil {
		return "", fmt.Errorf("ssh/config/ca: empty response")
	}
	pub, ok := sec.Data["public_key"].(string)
	if !ok || pub == "" {
		return "", fmt.Errorf("ssh/config/ca: missing public_key")
	}
	return pub, nil
}
