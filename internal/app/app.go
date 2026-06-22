// Package app wires config, Vault, and Store for CLI commands.
package app

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

type App struct {
	Cfg   *config.Config
	Vault *vaultc.Client
}

func New() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	v, err := vaultc.New(cfg.VaultAddr, config.SRERootCA, cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &App{Cfg: cfg, Vault: v}, nil
}

// EnsureLogin keeps a token alive like an agent:
//  1. Reuse a valid token.
//  2. Renew it if possible.
//  3. Re-authenticate with AppRole if credentials are available.
//  4. Fall back to interactive login.
func (a *App) EnsureLogin(ctx context.Context) error {
	if a.Vault.HasValidToken() {
		return nil
	}
	if a.Vault.Renewable() && a.Vault.TTL() > 0 {
		if err := a.Vault.Renew(ctx); err == nil {
			return nil
		}
	}
	if id, sec, ok := a.AppRoleCreds(); ok {
		if err := a.Vault.LoginAppRole(ctx, a.Cfg.AppRoleMount, id, sec); err == nil {
			return nil
		}
	}
	return a.Login(ctx, a.Cfg.AuthMethod)
}

// Login authenticates with userpass, oidc, or approle.
func (a *App) Login(ctx context.Context, method string) error {
	switch strings.ToLower(method) {
	case "oidc":
		ui.Infof(os.Stderr, "Vault OIDC SSO login (%s)", a.Cfg.VaultAddr)
		return a.Vault.LoginOIDC(ctx, a.Cfg.OIDCMount, a.Cfg.OIDCRole)
	case "approle":
		id, sec, ok := a.AppRoleCreds()
		if !ok {
			return fmt.Errorf("missing AppRole credentials (VCTL_ROLE_ID/VCTL_SECRET_ID or *_FILE)")
		}
		return a.Vault.LoginAppRole(ctx, a.Cfg.AppRoleMount, id, sec)
	case "", "userpass":
		return a.loginUserpass(ctx)
	default:
		return fmt.Errorf("unknown auth method: %s", method)
	}
}

// ReAuth ignores the current token and obtains a new one.
// It uses AppRole when possible and falls back to interactive auth.
func (a *App) ReAuth(ctx context.Context) error {
	if err := a.ReAuthNonInteractive(ctx); err == nil {
		return nil
	}
	return a.Login(ctx, a.Cfg.AuthMethod)
}

// ReAuthNonInteractive re-authenticates with AppRole only.
// It is used when stdin belongs to a child process and prompts would conflict.
func (a *App) ReAuthNonInteractive(ctx context.Context) error {
	id, sec, ok := a.AppRoleCreds()
	if !ok {
		return fmt.Errorf("missing AppRole credentials for non-interactive re-auth")
	}
	return a.Vault.LoginAppRole(ctx, a.Cfg.AppRoleMount, id, sec)
}

// AppRoleCreds resolves role_id and secret_id from values or files.
func (a *App) AppRoleCreds() (roleID, secretID string, ok bool) {
	roleID = firstNonEmpty(a.Cfg.AppRoleID, readFileTrim(a.Cfg.AppRoleIDFile))
	secretID = firstNonEmpty(a.Cfg.AppRoleSecretID, readFileTrim(a.Cfg.AppRoleSecretIDFile))
	return roleID, secretID, roleID != "" && secretID != ""
}

// RegisterAgent makes vctl self-sufficient after the first interactive login:
// it fetches the configured approle's role_id and a fresh secret_id and stores
// them, so later runs auto-authenticate without prompting. Best-effort — if the
// login token may not generate a secret_id, it returns an error the caller can
// surface without failing the login. No-op when approle creds already exist.
func (a *App) RegisterAgent(ctx context.Context) error {
	if _, _, ok := a.AppRoleCreds(); ok {
		return nil // already registered
	}
	role := a.Cfg.AppRoleSelfRole
	if role == "" {
		return fmt.Errorf("no approle_self_role configured")
	}
	rid, err := a.Vault.AppRoleRoleID(ctx, a.Cfg.AppRoleMount, role)
	if err != nil {
		return err
	}
	sid, err := a.Vault.GenerateSecretID(ctx, a.Cfg.AppRoleMount, role)
	if err != nil {
		return err
	}
	if a.Cfg.AppRoleIDFile == "" || a.Cfg.AppRoleSecretIDFile == "" {
		return fmt.Errorf("approle credential file paths not set")
	}
	if err := os.WriteFile(a.Cfg.AppRoleIDFile, []byte(rid+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(a.Cfg.AppRoleSecretIDFile, []byte(sid+"\n"), 0o600); err != nil {
		return err
	}
	return nil
}

func readFileTrim(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (a *App) loginUserpass(ctx context.Context) error {
	ui.Section(os.Stderr, "Vault login")
	ui.Infof(os.Stderr, "%s", a.Cfg.VaultAddr)
	reader := bufio.NewReader(os.Stdin)

	def := os.Getenv("USER")
	if def != "" {
		fmt.Fprintf(os.Stderr, "Username [%s]: ", def)
	} else {
		fmt.Fprint(os.Stderr, "Username: ")
	}
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		username = def
	}
	if username == "" {
		return fmt.Errorf("username is required")
	}

	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if err := a.Vault.LoginUserpass(ctx, username, string(pw)); err != nil {
		return err
	}
	ui.Successf(os.Stderr, "login succeeded")
	return nil
}

// OpenStore ensures login, requests dynamic DB credentials, and opens Postgres.
// rw selects the write role for sync/admin paths; otherwise it uses the read role.
func (a *App) OpenStore(ctx context.Context, rw bool) (*store.Store, error) {
	role := a.Cfg.DBRoleRO
	if rw {
		role = a.Cfg.DBRoleRW
	}
	return a.OpenStoreRole(ctx, role)
}

// OpenStatusStore opens Postgres with the narrow node-agent status role.
func (a *App) OpenStatusStore(ctx context.Context) (*store.Store, error) {
	return a.OpenStoreRole(ctx, a.Cfg.DBRoleStatus)
}

// LogAccess records one SSH access attempt to the central audit table using
// write credentials. It is best-effort: it opens a short-lived RW store, inserts
// one row, and returns any error for the caller to log without failing the SSH.
func (a *App) LogAccess(ctx context.Context, entry store.AccessEntry) error {
	st, err := a.OpenStore(ctx, true)
	if err != nil {
		return err
	}
	defer st.Close()
	return st.LogAccess(ctx, entry)
}

// OpenStoreRole opens Postgres with a specific Vault database role.
func (a *App) OpenStoreRole(ctx context.Context, role string) (*store.Store, error) {
	// getCreds runs before each new pool connection. It re-establishes the Vault
	// session if the token lapsed, then issues a fresh dynamic DB credential, so
	// a daemon holding the pool for hours never outlives a credential lease.
	getCreds := func(ctx context.Context) (string, string, error) {
		if err := a.EnsureLogin(ctx); err != nil {
			return "", "", err
		}
		user, pass, _, err := a.Vault.DBCreds(ctx, role)
		return user, pass, err
	}
	return store.Open(ctx, a.Cfg.DBHost, a.Cfg.DBPort, a.Cfg.DBName, getCreds, a.Cfg.DBServerName, config.SRERootCA)
}
