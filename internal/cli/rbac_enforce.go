package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// The RBAC decision logic lives in internal/authz. This file holds only the
// cobra wiring: tagging commands with their class (gate), the persistent gate
// hook (enforceRBAC), and the two constructors that adapt an *app.App into an
// authz.Authorizer for the CLI (lazy store) and the MCP server (open store).

// Class aliases keep the command tree readable (gate(cmd, "ssh", classMutate))
// while the canonical class values live in authz.
const (
	classRead   = authz.ClassRead
	classMutate = authz.ClassMutate
	classAdmin  = authz.ClassAdmin
)

// gate tags a command with its RBAC name and class so the persistent pre-run
// hook can enforce it. The class round-trips through cobra annotations as a
// string.
func gate(cmd *cobra.Command, name string, class authz.Class) *cobra.Command {
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
func enforceRBAC(cmd *cobra.Command) error {
	name := cmd.Annotations["rbac.command"]
	if name == "" {
		return nil
	}
	ctx := cmd.Context()
	a, err := newApp()
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
func newAuthorizer(a *app.App) *authz.Authorizer {
	return authz.New(a.Vault, func(ctx context.Context) (authz.GrantSource, func(), error) {
		st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
		if err != nil {
			return nil, nil, err
		}
		return st, func() { st.Close() }, nil
	})
}

// mcpAuthorizer wires an authorizer over a store the MCP handler already holds,
// so a tool call reuses its open connection instead of opening another.
func mcpAuthorizer(a *app.App, st *store.Store) *authz.Authorizer {
	return authz.NewWithGrants(a.Vault, st)
}
