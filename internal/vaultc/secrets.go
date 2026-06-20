package vaultc

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// SignSSH 는 공개키를 ssh/sign/<role> 로 서명해 OpenSSH 인증서 문자열을 돌려준다.
// 비밀(개인키)은 클라이언트에만 있고 Vault 로 가지 않는다.
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
		return "", fmt.Errorf("ssh/sign/%s: 빈 응답", role)
	}
	signed, ok := sec.Data["signed_key"].(string)
	if !ok || signed == "" {
		return "", fmt.Errorf("ssh/sign/%s: 응답에 signed_key 없음", role)
	}
	return signed, nil
}

// DBCreds 는 database/creds/<role> 에서 단명 Postgres 자격을 발급받는다.
func (c *Client) DBCreds(ctx context.Context, role string) (user, pass string, ttl time.Duration, err error) {
	sec, err := c.api.Logical().ReadWithContext(ctx, "database/creds/"+role)
	if err != nil {
		return "", "", 0, fmt.Errorf("database/creds/%s: %w", role, err)
	}
	if sec == nil || sec.Data == nil {
		return "", "", 0, fmt.Errorf("database/creds/%s: 빈 응답", role)
	}
	user, _ = sec.Data["username"].(string)
	pass, _ = sec.Data["password"].(string)
	if user == "" || pass == "" {
		return "", "", 0, fmt.Errorf("database/creds/%s: username/password 없음", role)
	}
	return user, pass, time.Duration(sec.LeaseDuration) * time.Second, nil
}

// CAPublicKey 는 ssh/config/ca 의 CA 공개키를 읽는다(배포·검증용).
func (c *Client) CAPublicKey(ctx context.Context) (string, error) {
	sec, err := c.api.Logical().ReadWithContext(ctx, "ssh/config/ca")
	if err != nil {
		return "", fmt.Errorf("ssh/config/ca: %w", err)
	}
	if sec == nil || sec.Data == nil {
		return "", fmt.Errorf("ssh/config/ca: 빈 응답")
	}
	pub, ok := sec.Data["public_key"].(string)
	if !ok || pub == "" {
		return "", fmt.Errorf("ssh/config/ca: public_key 없음")
	}
	return pub, nil
}
