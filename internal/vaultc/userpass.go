package vaultc

import (
	"context"
	"fmt"
)

// LoginUserpass 는 auth/userpass 로 로그인하고 토큰을 캐시한다(v1 기본).
func (c *Client) LoginUserpass(ctx context.Context, username, password string) error {
	sec, err := c.api.Logical().WriteWithContext(ctx, "auth/userpass/login/"+username, map[string]interface{}{
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("userpass 로그인 실패: %w", err)
	}
	return c.applyAuth(sec)
}
