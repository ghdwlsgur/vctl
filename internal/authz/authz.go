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
	"prune":    ClassMutate,
	"trust-ca": ClassMutate,
	"list":     ClassRead,
	"status":   ClassRead,
	"audit":    ClassRead,
	"session":  ClassRead,
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

// Authorizer answers authorization questions from a policy source and a
// (lazily opened) grant source.
type Authorizer struct {
	policies   PolicySource
	openGrants func(context.Context) (GrantSource, func(), error)
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
		return err
	}
	if az.rbacUninitialized {
		return fmt.Errorf("rbac: not initialized yet — an admin must run 'vctl sync --migrate' first")
	}
	if az.Allows(cmd.Name) {
		return nil
	}
	return fmt.Errorf("rbac: '%s' not permitted for %q — ask an admin to grant it:\n  vctl rbac grant <group> %s", cmd.Name, identity, cmd.Name)
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
	return nil
}
