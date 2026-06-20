package vaultc

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SignSSH signs a public key through ssh/sign/<role> and returns an OpenSSH cert.
// The private key remains client-side and is never sent to Vault.
func (c *Client) SignSSH(ctx context.Context, role, publicKey string, principals []string, ttl string) (string, error) {
	sec, err := c.api.Logical().WriteWithContext(ctx, "ssh/sign/"+role, map[string]interface{}{
		"public_key":       publicKey,
		"valid_principals": strings.Join(principals, ","),
		"ttl":              ttl,
	})
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
