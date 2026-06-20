package vaultc

import (
	"context"
	"fmt"
)

// LoginUserpass logs in through auth/userpass and caches the token.
func (c *Client) LoginUserpass(ctx context.Context, username, password string) error {
	sec, err := c.api.Logical().WriteWithContext(ctx, "auth/userpass/login/"+username, map[string]interface{}{
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("userpass login failed: %w", err)
	}
	return c.applyAuth(sec)
}
