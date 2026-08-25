package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/invcache"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The RBAC decision logic lives in internal/authz. This file holds only the
// cobra wiring: tagging commands with their class (gate), the persistent gate
// hook (enforceRBAC), and the constructor that adapts an *app.App into an
// authz.Authorizer for the CLI (lazy store). The MCP server wires its own in
// internal/mcp, over the store a tool call already holds.

// Class aliases keep this file readable while the canonical class values live
// in authz.
const (
	classRead   = authz.ClassRead
	classMutate = authz.ClassMutate
	classAdmin  = authz.ClassAdmin
)

// gate tags a command with its RBAC name so the persistent pre-run hook can
// enforce it. The class comes from the authz catalog rather than the call
// site: when the two were stated separately, gates accumulated names the
// catalog had never heard of, and those commands could not be granted except
// through "*" or an admin policy.
//
// An unknown name panics. The tree is wired on every invocation and under
// root_test, so a typo dies in CI, never in a release — the same contract as
// regexp.MustCompile.
func gate(cmd *cobra.Command, name string) *cobra.Command {
	class, ok := authz.ClassOf(name)
	if !ok {
		panic(fmt.Sprintf("rbac: gate %q is not in the authz catalog", name))
	}
	return tagRBAC(cmd, name, class)
}

// gateReadView tags a read-only view of a resource whose grant name is
// mutate-classed — `vctl ip` lists the ledger that a granted `ip set` writes.
// The gate still requires login; past that, read is default-allowed.
func gateReadView(cmd *cobra.Command, name string) *cobra.Command {
	if _, ok := authz.ClassOf(name); !ok {
		panic(fmt.Sprintf("rbac: gate %q is not in the authz catalog", name))
	}
	return tagRBAC(cmd, name, classRead)
}

// tagRBAC records the decision on the command. The class round-trips through
// cobra annotations as a string.
func tagRBAC(cmd *cobra.Command, name string, class authz.Class) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations["rbac.command"] = name
	cmd.Annotations["rbac.class"] = string(class)
	return cmd
}

// enforceRBAC is the persistent pre-run gate. It authenticates, then asks the
// authorizer whether the current identity may run this command. Ungated
// commands carry no annotation and pass straight through.
func enforceRBAC(env CommandEnv, cmd *cobra.Command) error {
	name := cmd.Annotations["rbac.command"]
	if name == "" {
		return nil
	}
	ctx := cmd.Context()
	a, err := env.newApp()
	if err != nil {
		return err
	}
	if err := a.EnsureLogin(ctx); err != nil {
		return err
	}
	return newAuthorizer(a).Check(ctx, authz.Command{
		Name:  name,
		Class: authz.Class(cmd.Annotations["rbac.class"]),
	})
}

// newAuthorizer wires the CLI's lazy authorizer: Vault supplies policies, and
// the read-only inventory store — the source of command grants — is opened only
// if a decision actually needs it (a non-admin mutate), then closed.
//
// It also carries the degraded-mode configuration, so a mutate decision made
// while Postgres is down falls back to the last grants Postgres confirmed,
// inside the configured window. Vault policies stay a live lookup either way.
func newAuthorizer(a *app.App) *authz.Authorizer {
	return authz.New(a.Vault, func(ctx context.Context) (authz.GrantSource, func(), error) {
		st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
		if err != nil {
			return nil, nil, err
		}
		return st, func() { st.Close() }, nil
	}).WithOffline(offlineConfig(a)).WithAdminPolicies(a.Cfg.AdminPolicies)
}

// cachedGrant translates a stored grant into the authorization layer's view of
// it. authz deliberately depends on nothing but the standard library, so the
// two types stay separate and this is the seam between them — one place, so the
// gate and `vctl cache status` cannot disagree about what they are looking at.
func cachedGrant(g invcache.GrantRecord) authz.CachedGrant {
	return authz.CachedGrant{Commands: g.Commands, ConfirmedAt: g.CapturedAt}
}

// offlineConfig adapts the app's snapshot cache into authz's degraded-mode
// ports. Returns nil when the cache is disabled, which turns offline
// authorization off entirely.
func offlineConfig(a *app.App) *authz.Offline {
	if a.Cfg.CacheDisabled {
		return nil
	}
	return &authz.Offline{
		Lookup: func(identity string) (authz.CachedGrant, bool) {
			g, ok := a.CachedGrants(identity)
			if !ok {
				return authz.CachedGrant{}, false
			}
			return cachedGrant(g), true
		},
		Record: a.RecordGrants,
		Window: a.Cfg.CacheOfflineWindow(),
		OnDegraded: func(command string, age time.Duration) {
			ui.Warnf(os.Stderr, "inventory database unreachable — '%s' authorized from cached grants confirmed %s ago",
				command, strutil.CompactDuration(age))
		},
	}
}
