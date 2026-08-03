// Package app wires config, Vault, and Store for CLI commands.
package app

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/dbcreds"
	"github.com/ghdwlsgur/vctl/internal/securefile"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

type App struct {
	Cfg   *config.Config
	Vault *vaultc.Client

	// OnSpoolFlush reports the result of replaying access records that were
	// queued while Postgres was unreachable. Optional; nil flushes silently.
	OnSpoolFlush func(sent int, err error)
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
	if ok, err := a.tryAppRoleLogin(ctx); ok && err == nil {
		return nil
	}
	// Kubernetes before the configured method, for the same reason AppRole is:
	// both are unattended, and a pod that could authenticate itself should not
	// fall through to a method that prompts.
	if ok, err := a.tryKubernetesLogin(ctx); ok && err == nil {
		return nil
	}
	return a.Login(ctx, a.Cfg.AuthMethod)
}

// Login authenticates with userpass, oidc, approle, or kubernetes.
func (a *App) Login(ctx context.Context, method string) error {
	switch strings.ToLower(method) {
	case "oidc":
		ui.Infof(os.Stderr, "Vault OIDC SSO login (%s)", a.Cfg.VaultAddr)
		return a.Vault.LoginOIDC(ctx, a.Cfg.OIDCMount, a.Cfg.OIDCRole)
	case "approle":
		ok, err := a.tryAppRoleLogin(ctx)
		if !ok {
			return fmt.Errorf("missing AppRole credentials (VCTL_ROLE_ID/VCTL_SECRET_ID or *_FILE)")
		}
		return err
	case "kubernetes":
		ok, err := a.tryKubernetesLogin(ctx)
		if !ok {
			return fmt.Errorf("kubernetes auth needs a role (VCTL_KUBERNETES_ROLE) and a projected service account token — is this running in a pod?")
		}
		return err
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
	ok, err := a.tryAppRoleLogin(ctx)
	if !ok {
		return fmt.Errorf("missing AppRole credentials for non-interactive re-auth")
	}
	return err
}

// AppRoleCreds resolves role_id and secret_id from values or files.
func (a *App) AppRoleCreds() (roleID, secretID string, ok bool) {
	roleID = strutil.FirstNonEmpty(a.Cfg.AppRoleID, readFileTrim(a.Cfg.AppRoleIDFile))
	secretID = strutil.FirstNonEmpty(a.Cfg.AppRoleSecretID, readFileTrim(a.Cfg.AppRoleSecretIDFile))
	return roleID, secretID, roleID != "" && secretID != ""
}

// tryKubernetesLogin logs in with the pod's ServiceAccount token. ok=false with
// a nil error means this is not a pod, or no role is configured, so the caller
// can fall through to another method — on a workstation there is no token file
// and that is the ordinary case rather than a failure.
//
// The token is read on every attempt. Projected ServiceAccount tokens are
// refreshed in place, so a process that cached the contents at startup would
// re-authenticate an hour later with an assertion Vault has stopped accepting.
func (a *App) tryKubernetesLogin(ctx context.Context) (ok bool, err error) {
	if a.Cfg.KubernetesRole == "" {
		return false, nil
	}
	jwt, found, err := vaultc.ReadServiceAccountToken(a.Cfg.KubernetesTokenFile)
	if err != nil {
		// Configured for kubernetes auth but the token is unreadable. That is a
		// real failure, not an absence, so report it rather than falling through
		// to a method that will ask for a password nobody is there to type.
		return true, err
	}
	if !found {
		return false, nil
	}
	return true, a.Vault.LoginKubernetes(ctx, a.Cfg.KubernetesMount, a.Cfg.KubernetesRole, jwt)
}

// tryAppRoleLogin logs in with stored AppRole creds. ok=false (with nil error)
// means no creds are configured; otherwise err is the login result.
func (a *App) tryAppRoleLogin(ctx context.Context) (ok bool, err error) {
	id, sec, have := a.AppRoleCreds()
	if !have {
		return false, nil
	}
	return true, a.Vault.LoginAppRole(ctx, a.Cfg.AppRoleMount, id, sec)
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
	if err := securefile.WriteAtomic(a.Cfg.AppRoleIDFile, []byte(rid+"\n"), 0o600); err != nil {
		return err
	}
	if err := securefile.WriteAtomic(a.Cfg.AppRoleSecretIDFile, []byte(sid+"\n"), 0o600); err != nil {
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

// Purpose names why a store is being opened. Each purpose maps to a specific
// Vault database role, so callers ask for a capability ("read inventory",
// "write audit") rather than naming a role string. The mapping lives in one
// place (roleFor), which is the only spot that knows the role names.
type Purpose int

const (
	PurposeInventoryRead Purpose = iota
	PurposeInventoryWrite
	PurposeStatus
	PurposeIdentity
	PurposeAuditRead
	PurposeAuditWrite
	PurposeAuditIngest
	PurposeMigrate
)

// roleFor maps a purpose to its configured Vault database role.
func (a *App) roleFor(p Purpose) string {
	switch p {
	case PurposeInventoryWrite:
		return a.Cfg.DBRoleRW
	case PurposeStatus:
		return a.Cfg.DBRoleStatus
	case PurposeIdentity:
		return a.Cfg.DBRoleIdentity
	case PurposeAuditRead:
		return a.Cfg.DBRoleAuditRO
	case PurposeAuditWrite:
		return a.Cfg.DBRoleAuditWrite
	case PurposeAuditIngest:
		return a.Cfg.DBRoleAuditIngest
	case PurposeMigrate:
		return a.Cfg.DBRoleMigrate
	default: // PurposeInventoryRead
		return a.Cfg.DBRoleRO
	}
}

// localDSNOnce holds the Vault-bypass notice to a single line per process.
// OpenStore runs on nearly every command path — LogAccess opens a store per SSH
// — so warning on each call would bury the command's own output.
var localDSNOnce sync.Once

// OpenStore ensures login, requests dynamic DB credentials for the purpose's
// Vault role, and opens Postgres.
func (a *App) OpenStore(ctx context.Context, p Purpose) (*store.Store, error) {
	if a.Cfg.LocalDBDSN != "" {
		// The local DSN ignores the purpose, so every caller shares one static
		// credential instead of its own least-privilege DB role. Say so on stderr:
		// a loopback address is also what a port-forward to the production database
		// looks like, and that combination should not pass unnoticed.
		localDSNOnce.Do(func() {
			ui.Warnf(os.Stderr, "VCTL_LOCAL_DB_DSN set: static local Postgres credential in use, bypassing Vault dynamic creds and per-purpose DB roles")
		})
		return store.OpenLocal(ctx, a.Cfg.LocalDBDSN)
	}
	return a.openRole(ctx, a.roleFor(p))
}

// LogAccess records one SSH access attempt to the central audit table using
// write credentials. It is best-effort: it opens a short-lived audit-write
// store, inserts one row, and returns any error for the caller to log without
// failing the SSH.
//
// When the write cannot reach Postgres the record is queued locally and the
// returned error is a *SpooledError, so the caller can say "pending" rather than
// "lost". A successful write also replays anything already queued — the moment a
// working audit connection exists is the moment to catch up.
func (a *App) LogAccess(ctx context.Context, entry store.AccessEntry) error {
	st, err := a.OpenStore(ctx, PurposeAuditWrite)
	if err != nil {
		return a.spoolAccess(entry, err)
	}
	defer st.Close()
	if err := st.LogAccess(ctx, entry); err != nil {
		return a.spoolAccess(entry, err)
	}
	a.drainSpool(ctx, st)
	return nil
}

// openRole opens Postgres with a specific Vault database role.
func (a *App) openRole(ctx context.Context, role string) (*store.Store, error) {
	// getCreds runs before each new pool connection. It re-establishes the Vault
	// session if the token lapsed, then asks the cache for a credential, so a
	// daemon holding the pool for hours never outlives a credential lease.
	//
	// The cache is what keeps connection recycling from meaning credential
	// issuance. The pool drops a connection roughly every 45 minutes; Vault
	// renews the same lease for up to its max_ttl, so those recycles reuse one
	// credential instead of creating a Postgres role apiece.
	//
	// The floor comes from the pool rather than a constant here: a credential
	// handed out now must still be valid for the whole life of the connection
	// that takes it. The renewal increment is the same span — asking for more
	// than max_ttl allows is harmless because Vault clamps it.
	minRemaining := store.MaxConnAge() + credentialSafetyMargin
	cache := dbcreds.New(vaultIssuer{app: a, role: role}, minRemaining, renewalIncrement)
	getCreds := func(ctx context.Context) (string, string, error) {
		if err := a.EnsureLogin(ctx); err != nil {
			return "", "", err
		}
		return cache.Get(ctx)
	}
	return store.Open(ctx, a.Cfg.DBHost, a.Cfg.DBPort, a.Cfg.DBName, getCreds, a.Cfg.DBServerName, config.SRERootCA)
}

const (
	// credentialSafetyMargin is the slack between a connection's maximum age and
	// the lease backing it, covering clock skew between this host and Vault plus
	// the time a slow connect spends between the credential check and first use.
	credentialSafetyMargin = 5 * time.Minute

	// renewalIncrement asks for far more time than any role will grant. Vault
	// clamps a renewal to what remains of the role's max_ttl, so over-asking
	// costs nothing and keeps this client from encoding a server-side setting it
	// does not own. Asking for exactly the floor instead would technically work
	// and would renew every few minutes to reach the same expiry.
	renewalIncrement = 24 * time.Hour
)

// vaultIssuer adapts the Vault client to dbcreds.Issuer.
type vaultIssuer struct {
	app  *App
	role string
}

func (v vaultIssuer) Issue(ctx context.Context) (vaultc.DBLease, error) {
	return v.app.Vault.DBCreds(ctx, v.role)
}

func (v vaultIssuer) Renew(ctx context.Context, leaseID string, increment time.Duration) (time.Duration, bool, error) {
	return v.app.Vault.RenewLease(ctx, leaseID, increment)
}
