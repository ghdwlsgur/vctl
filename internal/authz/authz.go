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
// the one place the command→class mapping lives; the grant picker, the
// `rbac check` command, and grant validation all read it through the accessors
// below so a new gated command is described in exactly one spot.
var gated = map[string]Class{
	"ssh":      ClassMutate,
	"exec":     ClassMutate,
	"sync":     ClassMutate,
	"trust-ca": ClassMutate,
	"list":     ClassRead,
	"status":   ClassRead,
	"audit":    ClassRead,
	"session":  ClassRead,
	// retention reports what is past its horizon and what it costs on disk; it
	// deletes nothing. It was "prune" and ClassMutate, guarding a deletion path
	// that could never run — see cli/retention.go. Deletion lives in the prune
	// CronJob, which does not go through vctl at all.
	"retention": ClassRead,
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

// Grantable returns "*" (all commands) followed by the sorted gated command
// names — the menu of things a grant can target.
func Grantable() []string {
	return append([]string{"*"}, GatedCommands()...)
}

// HasAdminPolicy reports whether the caller holds an admin Vault policy that
// bypasses command RBAC entirely.
func HasAdminPolicy(pols []string) bool {
	return slices.Contains(pols, "vctl-admin") || slices.Contains(pols, "sre-admin")
}

// IsUninitializedRBAC reports whether err is Postgres "undefined table" (42P01),
// meaning the RBAC schema has not been migrated yet. Callers treat this as
// "no grants" rather than a hard failure.
func IsUninitializedRBAC(err error) bool {
	return err != nil && strings.Contains(err.Error(), "42P01")
}

// PolicySource reports the caller's Vault identity and token policies. Satisfied
// by *vaultc.Client.
type PolicySource interface {
	TokenPolicies(ctx context.Context) ([]string, error)
	Identity(ctx context.Context) string
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
}

// WithOffline attaches degraded-mode behaviour and returns the authorizer, so
// wiring reads as one expression at the call site.
func (a *Authorizer) WithOffline(o *Offline) *Authorizer {
	a.offline = o
	return a
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

// Snapshot reads the caller's policies and, for non-admins, their command
// grants. It fails closed: a policy-lookup error is returned rather than
// silently treated as "no admin". An uninitialized RBAC schema is not an error —
// the caller is reported as having no grants.
func (a *Authorizer) Snapshot(ctx context.Context) (Authorization, error) {
	pols, err := a.policies.TokenPolicies(ctx)
	if err != nil {
		return Authorization{}, fmt.Errorf("rbac: token lookup: %w", err)
	}
	az := Authorization{Identity: a.policies.Identity(ctx), Policies: pols, Admin: HasAdminPolicy(pols)}
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
	pols, err := a.policies.TokenPolicies(ctx)
	if err != nil {
		return fmt.Errorf("rbac: token lookup: %w", err)
	}
	if HasAdminPolicy(pols) {
		return nil
	}
	switch cmd.Class {
	case ClassRead:
		return nil
	case ClassAdmin:
		return fmt.Errorf("rbac: '%s' is admin-only (needs vctl-admin or sre-admin)", cmd.Name)
	}
	identity := a.policies.Identity(ctx)
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
