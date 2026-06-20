// Package vaultc 는 vctl 가 Vault 와 주고받는 모든 것을 담는다.
//
// Vault Agent 를 쓰지 않는다 — 이 클라이언트가 직접 로그인하고, 토큰을 캐시하고,
// 만료 전 자동 갱신(renew-self)하며, SSH cert 서명과 동적 DB 자격 발급을 수행한다.
// 즉 별도 데몬 없이 "에이전트처럼" 토큰 수명을 관리한다.
package vaultc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type Client struct {
	api       *vault.Client
	tokenPath string
	tokenExp  time.Time
	renewable bool
}

type cachedToken struct {
	Token     string    `json:"token"`
	Expires   time.Time `json:"expires"`
	Renewable bool      `json:"renewable"`
}

// New 는 임베드된 사설 CA 로 TLS 를 구성한 Vault 클라이언트를 만들고,
// 캐시된 토큰이 있으면 즉시 적용한다.
func New(addr string, caPEM []byte, stateDir string) (*Client, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = addr
	if len(caPEM) > 0 {
		if err := cfg.ConfigureTLS(&vault.TLSConfig{CACertBytes: caPEM}); err != nil {
			return nil, fmt.Errorf("configure TLS: %w", err)
		}
	}
	api, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}
	c := &Client{api: api, tokenPath: filepath.Join(stateDir, "token")}
	c.loadToken()
	return c, nil
}

// HasValidToken 은 캐시 토큰이 살아있는지(만료 60초 여유) 반환한다.
func (c *Client) HasValidToken() bool {
	return c.api.Token() != "" && c.tokenExp.After(time.Now().Add(60*time.Second))
}

func (c *Client) loadToken() {
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return
	}
	var t cachedToken
	if err := json.Unmarshal(b, &t); err != nil {
		return
	}
	c.tokenExp = t.Expires
	c.renewable = t.Renewable
	if t.Token != "" && t.Expires.After(time.Now()) {
		c.api.SetToken(t.Token)
	}
}

func (c *Client) saveToken(token string, ttl time.Duration, renewable bool) error {
	exp := time.Now().Add(ttl)
	c.tokenExp = exp
	c.renewable = renewable
	c.api.SetToken(token)
	b, _ := json.Marshal(cachedToken{Token: token, Expires: exp, Renewable: renewable})
	return os.WriteFile(c.tokenPath, b, 0o600)
}

// applyAuth 는 로그인/갱신 응답의 토큰을 적용·캐시한다.
func (c *Client) applyAuth(sec *vault.Secret) error {
	if sec == nil || sec.Auth == nil || sec.Auth.ClientToken == "" {
		return fmt.Errorf("vault: 인증 응답에 토큰이 없습니다")
	}
	ttl := time.Duration(sec.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	return c.saveToken(sec.Auth.ClientToken, ttl, sec.Auth.Renewable)
}

// Token 은 현재 토큰 문자열을 반환한다(sink/exec 주입용).
func (c *Client) Token() string { return c.api.Token() }

// Renewable 은 현재 토큰이 갱신 가능한지 반환한다.
func (c *Client) Renewable() bool { return c.renewable }

// Expiry 는 캐시 토큰의 만료 시각을 반환한다.
func (c *Client) Expiry() time.Time { return c.tokenExp }

// TTL 은 남은 토큰 수명을 반환한다(없으면 0).
func (c *Client) TTL() time.Duration {
	if c.tokenExp.IsZero() {
		return 0
	}
	d := time.Until(c.tokenExp)
	if d < 0 {
		return 0
	}
	return d
}

// Renew 는 renew-self 로 토큰 수명을 연장한다(자격 재입력 불필요).
// max_ttl 도달 등으로 더 못 늘리면 에러를 돌려준다 → 호출부가 재인증 결정.
func (c *Client) Renew(ctx context.Context) error {
	if c.api.Token() == "" {
		return fmt.Errorf("토큰 없음")
	}
	sec, err := c.api.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("renew-self: %w", err)
	}
	return c.applyAuth(sec)
}

// Logout 은 캐시된 토큰을 폐기한다.
func (c *Client) Logout() error {
	c.api.ClearToken()
	c.tokenExp = time.Time{}
	c.renewable = false
	if err := os.Remove(c.tokenPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
