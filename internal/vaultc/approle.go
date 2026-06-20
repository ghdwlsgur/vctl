package vaultc

import (
	"context"
	"fmt"
)

// LoginAppRole performs non-interactive AppRole login.
// It is used by agent and exec for unattended re-authentication.
func (c *Client) LoginAppRole(ctx context.Context, mount, roleID, secretID string) error {
	if mount == "" {
		mount = "approle"
	}
	if roleID == "" || secretID == "" {
		return fmt.Errorf("approle: role_id/secret_id is empty")
	}
	sec, err := c.api.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return fmt.Errorf("approle login failed: %w", err)
	}
	return c.applyAuth(sec)
}
