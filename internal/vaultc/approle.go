package vaultc

import (
	"context"
	"fmt"
)

// LoginAppRole 는 approle 로 비대화식 로그인한다.
// agent/exec 의 무인 재인증(auto-auth) 경로 — 자격 재입력 없이 토큰을 새로 받는다.
func (c *Client) LoginAppRole(ctx context.Context, mount, roleID, secretID string) error {
	if mount == "" {
		mount = "approle"
	}
	if roleID == "" || secretID == "" {
		return fmt.Errorf("approle: role_id/secret_id 가 비어 있음")
	}
	sec, err := c.api.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", map[string]any{
		"role_id":   roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return fmt.Errorf("approle 로그인 실패: %w", err)
	}
	return c.applyAuth(sec)
}
