// Package vaultc contains all Vault interactions used by vctl.
//
// It logs in directly, caches tokens, renews before expiry, signs SSH
// certificates, and requests dynamic DB credentials without Vault Agent.
package vaultc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"

	"github.com/ghdwlsgur/vctl/internal/securefile"
)

type Client struct {
	api       *vault.Client
	tokenPath string

	// mu guards tokenExp and renewable. The underlying vault.Client locks its
	// own token, but these two are ours — and they are read from whatever
	// goroutine pgxpool opens a connection on (the credential callback checks
	// login first), while a login or renewal on another writes them. time.Time
	// is multi-word, so that read is a torn value, not just a stale one.
	mu        sync.Mutex
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
//
// The operator's environment does not get a say in where this client connects
// or whether it verifies the server. vault.DefaultConfig reads VAULT_* variables,
// and two of them would quietly undo what vctl is for: VAULT_SKIP_VERIFY turns
// certificate verification off before the embedded CA is even installed (the
// library's ConfigureTLS only ever sets InsecureSkipVerify to true, never back),
// and VAULT_AGENT_ADDR redirects every request to another process. A stale
// `export VAULT_SKIP_VERIFY=1` from a dev Vault must not send production tokens,
// OIDC codes, DB credentials and SSH signing requests over an unverified channel.
func New(addr string, caPEM []byte, stateDir string) (*Client, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = addr
	cfg.AgentAddress = ""
	if len(caPEM) > 0 {
		if err := cfg.ConfigureTLS(&vault.TLSConfig{CACertBytes: caPEM}); err != nil {
			return nil, fmt.Errorf("configure TLS: %w", err)
		}
	}
	pinTLSVerification(cfg)
	api, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("new vault client: %w", err)
	}
	c := &Client{api: api, tokenPath: filepath.Join(stateDir, "token")}
	c.loadToken()
	return c, nil
}

// pinTLSVerification makes sure the transport verifies the server no matter
// what the environment asked for. Only the flag is touched: the RootCAs that
// ConfigureTLS installed from the embedded CA stay as they are.
func pinTLSVerification(cfg *vault.Config) {
	if cfg == nil || cfg.HttpClient == nil {
		return
	}
	tr, ok := cfg.HttpClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		return
	}
	tr.TLSClientConfig.InsecureSkipVerify = false
}

// HasValidToken reports whether the cached token is valid with 60s of margin.
func (c *Client) HasValidToken() bool {
	c.mu.Lock()
	exp := c.tokenExp
	c.mu.Unlock()
	return c.api.Token() != "" && exp.After(time.Now().Add(60*time.Second))
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
	c.mu.Lock()
	c.tokenExp = t.Expires
	c.renewable = t.Renewable
	c.mu.Unlock()
	if t.Token != "" && t.Expires.After(time.Now()) {
		c.api.SetToken(t.Token)
	}
}

func (c *Client) saveToken(token string, ttl time.Duration, renewable bool) error {
	exp := time.Now().Add(ttl)
	c.mu.Lock()
	c.tokenExp = exp
	c.renewable = renewable
	c.mu.Unlock()
	c.api.SetToken(token)
	b, err := json.Marshal(cachedToken{Token: token, Expires: exp, Renewable: renewable})
	if err != nil {
		return err
	}
	return securefile.WriteAtomic(c.tokenPath, b, 0o600)
}

// applyAuth applies and caches a token from a login or renewal response.
// fallbackAuthTokenTTL is assumed when Vault returns a token without a lease
// duration (e.g. some root/periodic tokens), so renewal scheduling has a sane
// window rather than treating the token as already expired.
const fallbackAuthTokenTTL = time.Hour

func (c *Client) applyAuth(sec *vault.Secret) error {
	if sec == nil || sec.Auth == nil || sec.Auth.ClientToken == "" {
		return fmt.Errorf("vault auth response has no token")
	}
	ttl := time.Duration(sec.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = fallbackAuthTokenTTL
	}
	return c.saveToken(sec.Auth.ClientToken, ttl, sec.Auth.Renewable)
}

// Token returns the current token for sink files and exec injection.
func (c *Client) Token() string { return c.api.Token() }

// Renewable reports whether the current token can be renewed.
func (c *Client) Renewable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.renewable
}

// Expiry returns the cached token expiry time.
func (c *Client) Expiry() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tokenExp
}

// TTL returns the remaining token lifetime.
func (c *Client) TTL() time.Duration {
	exp := c.Expiry()
	if exp.IsZero() {
		return 0
	}
	d := time.Until(exp)
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

// TokenInfo is one LookupSelf's worth of answers about the current token.
// Identity, policies and auth method were three separate methods, each paying
// its own Vault round trip — and the RBAC gate asked for two of them back to
// back on every gated command.
type TokenInfo struct {
	// Identity is the human-readable per-person identity, used to attribute
	// audit rows. It prefers the username from token metadata (userpass sets
	// meta.username; OIDC sets it via the role's claim_mappings), so SSO
	// logins record the actual person rather than the role-based display_name
	// (e.g. "oidc-vctl"). Falls back to display_name, then "" — a token can
	// legitimately carry no name.
	Identity string

	// Policies is the effective policy set: token policies plus identity
	// (group-derived) policies. The app-layer RBAC uses it to detect
	// vctl-admin (bypass) — group membership grants vctl-admin via
	// identity_policies, so both keys are unioned.
	Policies []string

	// AuthMethod names the auth method that issued the token, read from
	// display_name ("approle", "userpass-albert" → "userpass").
	AuthMethod string
}

// LookupToken reads the current token's info in one round trip.
//
// A missing token and a failed lookup are both errors, distinct from a token
// that legitimately carries no name. Identity used to collapse all three
// states into "", and that "" went straight into audit rows — an SSH whose
// attribution failed was indistinguishable from one made by a nameless token.
func (c *Client) LookupToken(ctx context.Context) (TokenInfo, error) {
	if c.api.Token() == "" {
		return TokenInfo{}, fmt.Errorf("vault: not logged in")
	}
	sec, err := c.api.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return TokenInfo{}, fmt.Errorf("vault: token lookup: %w", err)
	}
	if sec == nil || sec.Data == nil {
		return TokenInfo{}, fmt.Errorf("vault: token lookup returned no data")
	}
	var info TokenInfo
	if meta, ok := sec.Data["meta"].(map[string]any); ok {
		for _, k := range []string{"username", "preferred_username", "email"} {
			if v, ok := meta[k].(string); ok && v != "" {
				info.Identity = v
				break
			}
		}
	}
	dn, _ := sec.Data["display_name"].(string)
	if info.Identity == "" {
		info.Identity = dn
	}
	if i := strings.IndexByte(dn, '-'); i > 0 {
		info.AuthMethod = dn[:i]
	} else {
		info.AuthMethod = dn
	}
	set := map[string]struct{}{}
	for _, key := range []string{"policies", "identity_policies"} {
		raw, ok := sec.Data[key].([]any)
		if !ok {
			continue
		}
		for _, p := range raw {
			if str, ok := p.(string); ok && str != "" {
				set[str] = struct{}{}
			}
		}
	}
	info.Policies = make([]string, 0, len(set))
	for p := range set {
		info.Policies = append(info.Policies, p)
	}
	return info, nil
}

// TokenIdentity is the RBAC gate's view: identity and policies from the one
// lookup, errors propagated. Satisfies authz.PolicySource.
func (c *Client) TokenIdentity(ctx context.Context) (string, []string, error) {
	info, err := c.LookupToken(ctx)
	if err != nil {
		return "", nil, err
	}
	return info.Identity, info.Policies, nil
}

// Identity returns the per-person identity for the current token, for audit
// attribution. A lookup failure is an error, not an empty name.
func (c *Client) Identity(ctx context.Context) (string, error) {
	info, err := c.LookupToken(ctx)
	if err != nil {
		return "", err
	}
	return info.Identity, nil
}

// TokenPolicies returns the effective policy set on the current token.
func (c *Client) TokenPolicies(ctx context.Context) ([]string, error) {
	info, err := c.LookupToken(ctx)
	if err != nil {
		return nil, err
	}
	return info.Policies, nil
}

// Logout clears the cached token.
func (c *Client) Logout() error {
	c.api.ClearToken()
	c.mu.Lock()
	c.tokenExp = time.Time{}
	c.renewable = false
	c.mu.Unlock()
	if err := os.Remove(c.tokenPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// TokenAuthMethod names the auth method that issued the current token.
//
// Vault's display_name carries it: "approle", "userpass-albert",
// "oidc-vctl". The part before the first hyphen is the method.
//
// Worth asking because it is not always the method that was configured. A
// workstation with an AppRole credential on disk could authenticate as the
// AppRole while its config named userpass, and nothing said so — the tool kept
// working for reads and returned 403 for everything else. Comparing the two is
// how that becomes visible instead of being diagnosed. Diagnostic, so a failed
// lookup is "" rather than an error: the row it feeds renders either way.
func (c *Client) TokenAuthMethod(ctx context.Context) string {
	info, err := c.LookupToken(ctx)
	if err != nil {
		return ""
	}
	return info.AuthMethod
}
