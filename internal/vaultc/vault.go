// Package vaultc contains all Vault interactions used by vctl.
//
// It logs in directly, caches tokens, renews before expiry, signs SSH
// certificates, and requests dynamic DB credentials without Vault Agent.
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

// New creates a Vault client configured with the embedded private CA.
// Cached tokens are loaded immediately when present.
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

// HasValidToken reports whether the cached token is valid with 60s of margin.
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

// applyAuth applies and caches a token from a login or renewal response.
func (c *Client) applyAuth(sec *vault.Secret) error {
	if sec == nil || sec.Auth == nil || sec.Auth.ClientToken == "" {
		return fmt.Errorf("vault auth response has no token")
	}
	ttl := time.Duration(sec.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	return c.saveToken(sec.Auth.ClientToken, ttl, sec.Auth.Renewable)
}

// Token returns the current token for sink files and exec injection.
func (c *Client) Token() string { return c.api.Token() }

// Renewable reports whether the current token can be renewed.
func (c *Client) Renewable() bool { return c.renewable }

// Expiry returns the cached token expiry time.
func (c *Client) Expiry() time.Time { return c.tokenExp }

// TTL returns the remaining token lifetime.
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

// Renew extends the current token with renew-self.
// When max_ttl prevents renewal, callers decide whether to re-authenticate.
func (c *Client) Renew(ctx context.Context) error {
	if c.api.Token() == "" {
		return fmt.Errorf("missing token")
	}
	sec, err := c.api.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return fmt.Errorf("renew-self: %w", err)
	}
	return c.applyAuth(sec)
}

// Logout clears the cached token.
func (c *Client) Logout() error {
	c.api.ClearToken()
	c.tokenExp = time.Time{}
	c.renewable = false
	if err := os.Remove(c.tokenPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
