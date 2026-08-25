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

	"github.com/ghdwlsgur/vctl/internal/auditspool"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/dbcreds"
	"github.com/ghdwlsgur/vctl/internal/securefile"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/timing"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

type App struct {
	Cfg   *config.Config
	Vault *vaultc.Client

	// OnSpoolFlush reports the result of replaying access records that were
	// queued while Postgres was unreachable — including the ones the spool had
	// to drop as unreadable, which a bare sent count would hide. Optional; nil
	// flushes silently.
	OnSpoolFlush func(res auditspool.Result, err error)

	// Interactive reports whether somebody is present to answer a prompt, and
	// decides whether the configured login method outranks the unattended ones.
	// Optional; nil asks the terminal.
	Interactive func() bool

	// loginMu serializes EnsureLogin. pgxpool opens connections concurrently
	// and each new connection's credential callback ensures login first, so a
	// lapsed token met a burst of connects with one login per connection —
	// four AppRole logins where one would do, or, on the interactive path, a
	// second password prompt racing the first. The check-then-authenticate
	// sequence has to be one critical section; the goroutine that loses the
	// race finds a valid token and returns.
	loginMu sync.Mutex
}

func New() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	// Before anything resolves a name — the Vault client below is the first to
	// do so, and it would otherwise pay the system resolver's timeout.
	config.UseDNSServer(cfg.DNSServer)
	v, err := vaultc.New(cfg.VaultAddr, config.SRERootCA, cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &App{Cfg: cfg, Vault: v}, nil
}

// EnsureLogin keeps a token alive like an agent:
//  1. Reuse a valid token.
//  2. Renew it if possible.
//  3. Use the configured method, when one was named and somebody can answer it.
//  4. Otherwise authenticate unattended — AppRole, then Kubernetes.
//  5. Fall back to the configured method anyway.
//
// Step 3 did not exist, and its absence was a quiet downgrade. AppRole went
// first whenever credentials happened to be on disk, so a workstation carrying
// both `auth_method: userpass` and a role-id became the AppRole's identity every
// time its token lapsed. Measured on a real one: the operator's own login was
// configured and never used, and vctl ran as vctl-user — a role that can read
// the inventory and little else. Reads kept working, so nothing looked wrong,
// while `vctl ssh`, `vctl edit` and `vctl openstack reconcile` all returned 403
// on paths that person's own identity holds.
//
// Naming a method is a statement about which identity this installation should
// have. AppRole is what to do when nobody is there to be asked, not a shortcut
// past that statement — so it still goes first whenever there is no terminal,
// which is every pod, timer and CI job.
func (a *App) EnsureLogin(ctx context.Context) error {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	if a.Vault.HasValidToken() {
		return nil
	}
	if a.Vault.Renewable() && a.Vault.TTL() > 0 {
		if err := a.Vault.Renew(ctx); err == nil {
			return nil
		}
	}
	for _, method := range a.loginOrder() {
		switch method {
		case loginConfigured:
			// Its failure is the answer. Falling through to AppRole from here
			// would reproduce the downgrade this exists to stop, and do it at
			// the one moment somebody is watching.
			return a.Login(ctx, a.Cfg.AuthMethod)
		case loginAppRole:
			if ok, err := a.tryAppRoleLogin(ctx); ok && err == nil {
				return nil
			}
		case loginKubernetes:
			if ok, err := a.tryKubernetesLogin(ctx); ok && err == nil {
				return nil
			}
		}
	}
	return a.Login(ctx, a.Cfg.AuthMethod)
}

// The ways EnsureLogin can obtain a token, in the order it tries them.
const (
	loginConfigured = "configured"
	loginAppRole    = "approle"
	loginKubernetes = "kubernetes"
)

// loginOrder is the sequence EnsureLogin walks.
//
// Split out because the order *is* the behaviour here, and the bug was in the
// order: with it inline, a test could only reach the predicate below and would
// still pass with the whole branch deleted.
//
// Kubernetes stays behind AppRole for the reason it always did — both are
// unattended, and a pod that can authenticate itself should not fall through to
// something that prompts.
func (a *App) loginOrder() []string {
	if a.preferConfiguredLogin() {
		return []string{loginConfigured}
	}
	return []string{loginAppRole, loginKubernetes, loginConfigured}
}

// preferConfiguredLogin reports whether the named method should go ahead of the
// unattended ones.
//
// Only for a method that asks a human something. "approle" and "kubernetes"
// name the unattended paths themselves, so preferring them here would be the
// same order by a longer route, and an unset method expresses no preference at
// all. Without a terminal there is nobody to ask, whatever the config says.
func (a *App) preferConfiguredLogin() bool {
	switch strings.ToLower(a.Cfg.AuthMethod) {
	case "userpass", "oidc":
		return a.interactive()
	default:
		return false
	}
}

// interactive is injectable so the login order can be tested without a tty.
func (a *App) interactive() bool {
	if a.Interactive != nil {
		return a.Interactive()
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
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
	PurposeAuditPrune
	PurposeOpenStackPrune
	PurposeOpenStackReconcile
	PurposeMigrate
	purposeCount
)

// roleFor maps a purpose to its configured Vault database role. Unknown values
// are rejected rather than inheriting read access: adding a purpose without an
// explicit least-privilege decision must fail closed.
func (a *App) roleFor(p Purpose) (string, error) {
	switch p {
	case PurposeInventoryRead:
		return a.Cfg.DBRoleRO, nil
	case PurposeInventoryWrite:
		return a.Cfg.DBRoleRW, nil
	case PurposeStatus:
		return a.Cfg.DBRoleStatus, nil
	case PurposeIdentity:
		return a.Cfg.DBRoleIdentity, nil
	case PurposeAuditRead:
		return a.Cfg.DBRoleAuditRO, nil
	case PurposeAuditWrite:
		return a.Cfg.DBRoleAuditWrite, nil
	case PurposeAuditIngest:
		return a.Cfg.DBRoleAuditIngest, nil
	case PurposeAuditPrune:
		return a.Cfg.DBRoleAuditPrune, nil
	case PurposeOpenStackPrune:
		return a.Cfg.DBRoleOpenStackPrune, nil
	case PurposeOpenStackReconcile:
		return a.Cfg.DBRoleReconcile, nil
	case PurposeMigrate:
		return a.Cfg.DBRoleMigrate, nil
	default:
		return "", fmt.Errorf("unknown database purpose %d", p)
	}
}

// localDSNOnce holds the Vault-bypass notice to a single line per process.
// OpenStore runs on nearly every command path — LogAccess opens a store per SSH
// — so warning on each call would bury the command's own output.
var localDSNOnce sync.Once

// OpenStore ensures login, requests dynamic DB credentials for the purpose's
// Vault role, and opens Postgres.
func (a *App) OpenStore(ctx context.Context, p Purpose) (*store.Store, error) {
	role, err := a.roleFor(p)
	if err != nil {
		return nil, err
	}
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
	workload := store.WorkloadInteractive
	switch p {
	case PurposeStatus, PurposeAuditIngest, PurposeAuditPrune, PurposeOpenStackPrune, PurposeOpenStackReconcile:
		workload = store.WorkloadSerial
	}
	return a.openRole(ctx, role, workload)
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
func (a *App) openRole(ctx context.Context, role string, workload store.Workload) (*store.Store, error) {
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
	// Timed as three separate things because they cost and fail differently:
	// a cached token skips the login entirely, the credential is a Postgres
	// role Vault creates on demand, and the rest is TLS and a ping.
	//
	// getCreds runs *inside* store.Open, so its time is subtracted below rather
	// than reported twice — percentages that sum past 100 are how a nested
	// measurement misleads.
	// Guarded, because the pool decides when this runs and how many at once.
	//
	// getCreds is the pool's credential callback, not a step in this function.
	// pgxpool opens connections concurrently and reopens them long after Open
	// has returned, so an unguarded += here is a data race on both counts: two
	// connects racing the same add, and later connects mutating a variable
	// nothing reads any more.
	var (
		credentialMu   sync.Mutex
		credentialTime time.Duration
	)
	getCreds := func(ctx context.Context) (string, string, error) {
		done := timing.Start("vault-login")
		if err := a.EnsureLogin(ctx); err != nil {
			done()
			return "", "", err
		}
		done()
		at := time.Now()
		user, pass, err := cache.Get(ctx)
		credentialMu.Lock()
		credentialTime += time.Since(at)
		credentialMu.Unlock()
		return user, pass, err
	}
	openedAt := time.Now()
	st, err := store.OpenFor(ctx, a.Cfg.DBHost, a.Cfg.DBPort, a.Cfg.DBName, getCreds, a.Cfg.DBServerName, config.SRERootCA, workload)
	credentialMu.Lock()
	spent := credentialTime
	credentialMu.Unlock()
	timing.Record("db-credential", spent)
	timing.Record("db-connect", time.Since(openedAt)-spent)
	return st, err
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
