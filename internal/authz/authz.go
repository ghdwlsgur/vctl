// Package authz is the single owner of vctl's app-layer RBAC decision logic.
//
// Vault token policies are the authoritative security boundary (they gate SSH
// signing, audit reads, and database roles). App-layer RBAC is an additional
// client-side grant check on top of that boundary. Before this package the same
// decision — admin bypass, read default-allow, uninitialized-RBAC handling, and
// fail-closed policy lookups — was reassembled in four places (the CLI gate, the
// MCP tool gate, `rbac whoami`, and `rbac check`), which let them drift. Now the
// primitives and the composed Snapshot/Check live here so all callers agree.
package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Class ranks a command by how much authority it needs. Read commands are
// allowed to any authenticated user; mutate commands need an explicit grant;
// admin commands need an admin policy.
type Class string

const (
	ClassRead   Class = "read"
	ClassMutate Class = "mutate"
	ClassAdmin  Class = "admin"
)

// gated is the canonical catalog of RBAC-gated commands and their class. It is
// the one place the command→class mapping lives; the CLI gate derives a
// command's class from it, and the grant picker, the `rbac check` command, and
// grant validation all read it through the accessors below so a new gated
// command is described in exactly one spot.
//
// The catalog and the command tree must agree in both directions: a gate whose
// name is missing here is a mutate command nobody can grant except through "*"
// or an admin policy, and an entry no gate carries describes a gate that does
// not exist. Both happened — `vctl openstack farm state` once mutated with no
// grant path, and status/audit/session sat here for commands that had long
// been ungated. internal/cli's TestEveryGateMatchesTheCatalog walks the tree
// so neither drift can come back.
var gated = map[string]Class{
	// Access.
	"ssh":     ClassMutate,
	"exec":    ClassMutate,
	"inject":  ClassMutate,
	"install": ClassMutate,
	// Inventory writes.
	"add":    ClassMutate,
	"delete": ClassMutate,
	"edit":   ClassMutate,
	"sync":   ClassMutate,
	// Ledgers and topology. A grant of "ip" authorizes the subcommands that
	// write the address ledger; listing it is a read view, default-allowed.
	"ip":             ClassMutate,
	"wg":             ClassRead,
	"wg-sync":        ClassMutate,
	"openstack-farm": ClassMutate,
	// The rbac surface itself: reads are default-allowed, mutations are
	// admin-only — a grant must not be able to mint further grants.
	"users":  ClassRead,
	"list":   ClassRead,
	"whoami": ClassRead,
	"check":  ClassRead,
	"admin":  ClassAdmin,
	// retention reports what is past its horizon and what it costs on disk; it
	// deletes nothing. The hidden prune automation command is intentionally not
	// in this human RBAC catalog; its delete-only Vault role is the authorization.
	"retention": ClassRead,
	// Secrets. What `vctl kv` may list and read is decided by Vault's own path
	// policy, on the server, for every call — a boundary both authoritative and
	// finer than a command grant could be, since a token allowed kv/teams/a/*
	// and nothing else is answered per path. Read class, then: login required,
	// and Vault decides. An app-layer grant is not asked for because there is
	// nothing it could add except a second place to keep the same rule.
	"kv": ClassRead,
}

// ClassOf reports the class of a gated command; ok is false for an unknown
// (ungated) command name.
func ClassOf(name string) (class Class, ok bool) {
	class, ok = gated[name]
	return class, ok
}

// GatedCommands returns the gated command names, sorted.
func GatedCommands() []string {
	out := make([]string, 0, len(gated))
	for c := range gated {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// GrantableCommands returns the sorted names a grant can meaningfully target:
// the mutate class only. Read commands are allowed to any authenticated user
// and admin commands follow the Vault policy, so granting either changes
// nothing — offering them in the menu would let an admin believe it had.
func GrantableCommands() []string {
	out := make([]string, 0, len(gated))
	for c, class := range gated {
		if class == ClassMutate {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// Grantable returns "*" (all commands) followed by the sorted grantable
// command names — the menu of things a grant can target.
func Grantable() []string {
	return append([]string{"*"}, GrantableCommands()...)
}

// HasAdminPolicy reports whether the caller holds one of the admin Vault
// policies that bypass command RBAC entirely. The names are the caller's to
// supply — they are organization-specific surface (config admin_policies,
// compiled defaults in defaults_sre.go) and hard-coding them here made the
// one bypass in the system unrenameable without editing this package. An
// empty admins list admits nobody, which is the failing-closed reading of a
// configuration that names no admins.
func HasAdminPolicy(pols, admins []string) bool {
	for _, a := range admins {
		if slices.Contains(pols, a) {
			return true
		}
	}
	return false
}

// ErrUninitialized reports that the RBAC schema has never been migrated.
// Grant sources wrap it around their "table does not exist" failures, so this
// package — which deliberately depends on nothing but the standard library —
// can classify the condition without sniffing SQLSTATE text out of an error
// string. The sniff was how any failure whose message happened to carry
// "42P01" (a table name, a quoted query, a nested error) read as "no grants
// yet" on the path that builds authorization answers.
var ErrUninitialized = errors.New("rbac schema not initialized")

// IsUninitializedRBAC reports whether err means the RBAC schema has not been
// migrated yet. Callers treat this as "no grants" rather than a hard failure.
func IsUninitializedRBAC(err error) bool {
	return errors.Is(err, ErrUninitialized)
}

// PolicySource reports the caller's Vault identity and effective token
// policies — one answer, because they come from one token lookup and the gate
// needs both. As two methods, every gated command paid two Vault round trips,
// and the identity's lookup errors were silently collapsed into "". Satisfied
// by *vaultc.Client.
type PolicySource interface {
	TokenIdentity(ctx context.Context) (identity string, policies []string, err error)
}

// GrantSource reads a user's app-RBAC command grants. Satisfied by *store.Store.
type GrantSource interface {
	RBACCommandsForUser(ctx context.Context, user string) (map[string]bool, error)
}

// Command names a gated command and its class, as recorded on the cobra command
// that Check is guarding.
type Command struct {
	Name  string
	Class Class
}

// Authorization is a snapshot of the caller's identity and effective grants,
// shared by the CLI gate, the MCP tool gate, and whoami so they agree on admin
// status and granted commands.
type Authorization struct {
	Identity string
	Policies []string
	Admin    bool
	// Commands holds the caller's app-RBAC grants. It is nil when the caller is
	// an admin (grants don't apply) or when RBAC is uninitialized.
	Commands map[string]bool

	// rbacUninitialized records that the grant lookup hit an unmigrated schema.
	// Kept unexported: it drives Check's friendly "not initialized" message while
	// leaving the exported view (Allows, whoami) to treat the caller as ungranted.
	rbacUninitialized bool
}

// Allows reports whether the caller may run the named gated command: admins and
// a "*" grant allow anything, otherwise the exact command must be granted.
func (az Authorization) Allows(command string) bool {
	return az.Admin || az.Commands["*"] || az.Commands[command]
}

// CachedGrant is one identity's grants as last confirmed against Postgres, with
// the time of that confirmation. Declared here rather than imported so this
// package keeps depending on nothing but the standard library.
type CachedGrant struct {
	Commands    []string
	ConfirmedAt time.Time
}

// Has reports whether the cached grant covers a command, honouring "*".
func (g CachedGrant) Has(command string) bool {
	return slices.Contains(g.Commands, "*") || slices.Contains(g.Commands, command)
}

// Age is how long ago Postgres last confirmed the grant.
//
// A confirmation stamped in the future means a skewed clock or an edited cache;
// it is clamped to zero so the value stays reportable. Clamping cannot make an
// expired grant usable — Expired treats a non-positive window as expired — and
// local tampering is not something a local verifier can defend against anyway.
func (g CachedGrant) Age(now time.Time) time.Duration {
	return max(now.Sub(g.ConfirmedAt), 0)
}

// Expired reports whether the grant has aged out of the offline window and may
// no longer authorize anything. A window of zero or less means offline
// authorization is switched off, which is expiry for every grant.
//
// This is the single owner of the rule. `vctl cache status` renders the same
// verdict by calling it rather than recomputing the comparison, which is how the
// two drifted apart the first time.
func (g CachedGrant) Expired(now time.Time, window time.Duration) bool {
	return window <= 0 || g.Age(now) > window
}

// offlineAllowed lists the gated commands a cached grant may authorize while
// the grant source is unreachable.
//
// It is short on purpose. Every other mutate command writes to the inventory
// database (sync, ip set/rm, wg sync) or is one-time onboarding
// (trust-ca), so allowing them offline would buy nothing and widen the window in
// which a stale grant matters. `ssh` is the command an operator needs during an
// outage, and it is the one the Vault SSH CA independently gates.
var offlineAllowed = map[string]bool{"ssh": true}

// Offline configures degraded-mode authorization: what to do when the grant
// source cannot be reached.
//
// The design constraint is that degraded mode must never be more permissive than
// the normal path, or blocking your own database access becomes a privilege
// escalation. Every offline decision therefore requires a grant that Postgres
// previously confirmed, restricts the command set further (offlineAllowed), and
// expires (Window). Vault token policies are not cached at all — they are the
// authoritative boundary, and they stay a live lookup.
type Offline struct {
	// Lookup returns the identity's last confirmed grants.
	Lookup func(identity string) (CachedGrant, bool)
	// Record stores grants after a successful online lookup.
	Record func(identity string, commands []string)
	// Window bounds how old a confirmation may be. Zero disables offline
	// authorization entirely.
	Window time.Duration
	// OnDegraded is invoked when a command is allowed on cached grants, so the
	// caller can warn. Optional.
	OnDegraded func(command string, age time.Duration)
	// Now is the clock, injectable for tests. Defaults to time.Now.
	Now func() time.Time
}

func (o *Offline) now() time.Time {
	if o != nil && o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// enabled reports whether offline authorization is configured and permitted.
func (o *Offline) enabled() bool {
	return o != nil && o.Lookup != nil && o.Window > 0
}

// Authorizer answers authorization questions from a policy source and a
// (lazily opened) grant source.
type Authorizer struct {
	policies   PolicySource
	openGrants func(context.Context) (GrantSource, func(), error)
	offline    *Offline
	admins     []string
}

// WithOffline attaches degraded-mode behaviour and returns the authorizer, so
// wiring reads as one expression at the call site.
func (a *Authorizer) WithOffline(o *Offline) *Authorizer {
	a.offline = o
	return a
}

// WithAdminPolicies names the Vault policies that bypass command RBAC. An
// authorizer given none admits no admins — see HasAdminPolicy.
func (a *Authorizer) WithAdminPolicies(admins []string) *Authorizer {
	a.admins = admins
	return a
}

// adminsLabel renders the configured admin policies for denial messages, so
// the message names the policies this installation actually uses.
func (a *Authorizer) adminsLabel() string {
	if len(a.admins) == 0 {
		return "an admin policy, and none are configured"
	}
	return strings.Join(a.admins, " or ")
}

// New builds an Authorizer whose grant source is opened lazily — only when a
// decision actually needs grants (a non-admin mutate). Read and admin-only
// decisions never invoke openGrants, so they never pay to open a store. The
// returned cleanup func (may be nil) is called once the grants have been read.
func New(policies PolicySource, openGrants func(context.Context) (GrantSource, func(), error)) *Authorizer {
	return &Authorizer{policies: policies, openGrants: openGrants}
}

// NewWithGrants builds an Authorizer over an already-open grant source (e.g. a
// store the caller already holds), for callers that don't need lazy opening.
func NewWithGrants(policies PolicySource, grants GrantSource) *Authorizer {
	return New(policies, func(context.Context) (GrantSource, func(), error) {
		return grants, nil, nil
	})
}

// Snapshot reads the caller's identity and policies and, for non-admins,
// their command grants. It fails closed: a token-lookup error is returned
// rather than silently treated as "no admin, no name". An uninitialized RBAC
// schema is not an error — the caller is reported as having no grants.
func (a *Authorizer) Snapshot(ctx context.Context) (Authorization, error) {
	identity, pols, err := a.policies.TokenIdentity(ctx)
	if err != nil {
		return Authorization{}, fmt.Errorf("rbac: token lookup: %w", err)
	}
	az := Authorization{Identity: identity, Policies: pols, Admin: HasAdminPolicy(pols, a.admins)}
	if az.Admin {
		return az, nil
	}
	if err := a.loadGrants(ctx, &az); err != nil {
		return az, err
	}
	return az, nil
}

// Check enforces the gate for one command, mirroring Snapshot's fail-closed
// policy lookup but short-circuiting so read/admin decisions never open the
// grant source:
//
//	ungated command      → allow
//	admin policy         → allow (bypass)
//	read class           → allow (default-allow to any authenticated user)
//	admin class          → deny (admin-only)
//	mutate class         → allow only with a matching grant
func (a *Authorizer) Check(ctx context.Context, cmd Command) error {
	if cmd.Name == "" {
		return nil // ungated command
	}
	identity, pols, err := a.policies.TokenIdentity(ctx)
	if err != nil {
		return fmt.Errorf("rbac: token lookup: %w", err)
	}
	if HasAdminPolicy(pols, a.admins) {
		return nil
	}
	switch cmd.Class {
	case ClassRead:
		return nil
	case ClassAdmin:
		return fmt.Errorf("rbac: '%s' is admin-only (needs %s)", cmd.Name, a.adminsLabel())
	}
	if identity == "" {
		return fmt.Errorf("rbac: cannot determine your identity — run 'vctl login'")
	}
	az := Authorization{Identity: identity}
	if err := a.loadGrants(ctx, &az); err != nil {
		return a.checkOffline(cmd, identity, err)
	}
	if az.rbacUninitialized {
		return fmt.Errorf("rbac: not initialized yet — an admin must run 'vctl sync --migrate' first")
	}
	if az.Allows(cmd.Name) {
		return nil
	}
	return fmt.Errorf("rbac: '%s' not permitted for %q — ask an admin to grant it:\n  vctl rbac grant <group> %s", cmd.Name, identity, cmd.Name)
}

// checkOffline decides a mutate command when the grant source is unreachable.
//
// It is deliberately stricter than the online path at every step — the command
// must be in offlineAllowed, a prior online confirmation must exist, that
// confirmation must be inside the window, and it must actually carry the grant —
// so there is no version of "make Postgres unreachable" that grants more than
// being online would. When offline authorization is not configured, the original
// failure is returned unchanged.
func (a *Authorizer) checkOffline(cmd Command, identity string, cause error) error {
	if !a.offline.enabled() {
		return cause
	}
	if !offlineAllowed[cmd.Name] {
		return fmt.Errorf("rbac: '%s' needs the inventory database and it is unreachable: %w", cmd.Name, cause)
	}
	grant, ok := a.offline.Lookup(identity)
	if !ok {
		return fmt.Errorf("rbac: inventory database unreachable and no cached authorization for %q — "+
			"run '%s' once while it is reachable to cache one: %w", identity, cmd.Name, cause)
	}
	now := a.offline.now()
	age := grant.Age(now)
	if grant.Expired(now, a.offline.Window) {
		return fmt.Errorf("rbac: inventory database unreachable and the cached authorization for %q expired "+
			"(confirmed %s ago, offline window %s): %w", identity, age.Truncate(time.Minute), a.offline.Window, cause)
	}
	if !grant.Has(cmd.Name) {
		return fmt.Errorf("rbac: '%s' not permitted for %q by the cached authorization — "+
			"ask an admin to grant it:\n  vctl rbac grant <group> %s", cmd.Name, identity, cmd.Name)
	}
	if a.offline.OnDegraded != nil {
		a.offline.OnDegraded(cmd.Name, age)
	}
	return nil
}

// recordGrants caches a freshly confirmed grant set for offline use.
func (a *Authorizer) recordGrants(identity string, commands map[string]bool) {
	if a.offline == nil || a.offline.Record == nil || identity == "" {
		return
	}
	list := make([]string, 0, len(commands))
	for c, granted := range commands {
		if granted {
			list = append(list, c)
		}
	}
	a.offline.Record(identity, list)
}

// loadGrants opens the grant source, reads the caller's grants into az, and
// closes the source. An uninitialized RBAC schema sets az.rbacUninitialized and
// leaves Commands nil rather than erroring.
func (a *Authorizer) loadGrants(ctx context.Context, az *Authorization) error {
	gs, cleanup, err := a.openGrants(ctx)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}
	cmds, err := gs.RBACCommandsForUser(ctx, az.Identity)
	if err != nil {
		if IsUninitializedRBAC(err) {
			az.rbacUninitialized = true
			return nil
		}
		return err
	}
	az.Commands = cmds
	a.recordGrants(az.Identity, cmds)
	return nil
}
