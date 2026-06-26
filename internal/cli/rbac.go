package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// --- RBAC layer 2 (app-layer, CLI-managed) -----------------------------------
//
// Vault (layer 1) does the coarse bootstrap: vctl-admin vs vctl-user (everyone
// gets the ssh-sign capability; this app layer decides who may actually ssh).
// This layer is the fine-grained, admin-managed command RBAC stored centrally
// in Postgres. Enforcement (enforceRBAC) gates each command by its annotation:
//
//	classRead   — default allow to any authenticated user (list/status/audit)
//	classMutate — default DENY; needs a group grant (ssh/exec/sync/prune/trust-ca)
//	classAdmin  — vctl-admin only, not delegatable (the `vctl rbac` mutations)
//
// vctl-admin (layer 1) always bypasses, so admins can never lock themselves out.

const (
	classRead   = "read"
	classMutate = "mutate"
	classAdmin  = "admin"
)

// gatedCommands is the set of command names a grant may reference (plus "*").
// Keeping it explicit rejects typos in `vctl rbac grant <group> <command>`.
var gatedCommands = map[string]string{
	"ssh":      classMutate,
	"exec":     classMutate,
	"sync":     classMutate,
	"prune":    classMutate,
	"trust-ca": classMutate,
	"list":     classRead,
	"status":   classRead,
	"audit":    classRead,
	"session":  classRead,
}

// gate tags a command with its RBAC name + class so the root PersistentPreRunE
// can enforce it. Returns the command for inline use in AddCommand.
func gate(cmd *cobra.Command, name, class string) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations["rbac.command"] = name
	cmd.Annotations["rbac.class"] = class
	return cmd
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// hasAdminPolicy reports whether the token carries an admin policy that bypasses
// the app-layer RBAC: vctl-admin (vctl manager) or sre-admin (org superuser).
// sre-admin is org full-power, so it must bypass — and the workstation AppRole
// commonly carries sre-admin rather than the OIDC-group-derived vctl-admin.
func hasAdminPolicy(pols []string) bool {
	return containsStr(pols, "vctl-admin") || containsStr(pols, "sre-admin")
}

// isUninitializedRBAC reports a "relation does not exist" (SQLSTATE 42P01): the
// rbac_* tables aren't migrated yet. Run 'vctl sync --migrate' as an admin.
func isUninitializedRBAC(err error) bool {
	return err != nil && strings.Contains(err.Error(), "42P01")
}

// enforceRBAC runs in the root PersistentPreRunE for every command. Commands
// without an rbac annotation are ungated (login/token/agent/daemons/ca).
func enforceRBAC(cmd *cobra.Command) error {
	name := cmd.Annotations["rbac.command"]
	if name == "" {
		return nil // ungated
	}
	class := cmd.Annotations["rbac.class"]
	ctx := cmd.Context()

	a, err := newApp()
	if err != nil {
		return err
	}
	if err := a.EnsureLogin(ctx); err != nil {
		return err
	}
	// Layer 1: an admin policy (vctl-admin or sre-admin) bypasses everything —
	// including the DB lookup below, so admins work before migration 006 runs.
	pols, err := a.Vault.TokenPolicies(ctx)
	if err != nil {
		return fmt.Errorf("rbac: token lookup: %w", err)
	}
	if hasAdminPolicy(pols) {
		return nil
	}
	switch class {
	case classRead:
		return nil // default allow
	case classAdmin:
		return fmt.Errorf("rbac: '%s' is admin-only (needs vctl-admin or sre-admin)", name)
	}
	// classMutate: needs a group grant.
	user := a.Vault.Identity(ctx)
	if user == "" {
		return fmt.Errorf("rbac: cannot determine your identity — run 'vctl login'")
	}
	st, err := a.OpenStore(ctx, false)
	if err != nil {
		return err
	}
	defer st.Close()
	cmds, err := st.RBACCommandsForUser(ctx, user)
	if err != nil {
		if isUninitializedRBAC(err) {
			return fmt.Errorf("rbac: not initialized yet — an admin must run 'vctl sync --migrate' first")
		}
		return err
	}
	if cmds["*"] || cmds[name] {
		return nil
	}
	return fmt.Errorf("rbac: '%s' not permitted for %q — ask an admin to grant it:\n  vctl rbac grant <group> %s", name, user, name)
}

func rbacCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rbac",
		Short: "Manage app-layer command RBAC (groups, members, grants)",
		Long: `rbac manages the fine-grained, admin-managed command permissions (layer 2).

Vault does the coarse bootstrap (vctl-admin vs vctl-user). On top of
that, admins group users and grant them specific commands here. Non-admins may
run read commands (list/status/audit) by default; mutate/connect commands
(ssh/exec/sync/prune/trust-ca) need a group grant. Admins (vctl-admin) bypass.`,
	}
	cmd.AddCommand(rbacAssignCmd(), rbacGroupCmd(), rbacMemberCmd(), rbacGrantCmd(), rbacRevokeCmd(), rbacWhoamiCmd(), rbacCheckCmd())
	return cmd
}

// rbacAssignCmd is the convenient interactive assigner: pick a group, then
// multi-select users to add as members. Candidate users come from access_log +
// existing members (RBACCandidateUsers). Admin-only.
func rbacAssignCmd() *cobra.Command {
	return gate(&cobra.Command{
		Use:   "assign [group]",
		Short: "Interactively add users to a group (pick group → select users)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return withStore(ctx, true, func(_ *app.App, st *store.Store) error {
				// 1) group: arg, or pick from the list.
				group := ""
				if len(args) == 1 {
					group = args[0]
				} else {
					groups, err := st.RBACGroups(ctx)
					if err != nil {
						return err
					}
					if len(groups) == 0 {
						return fmt.Errorf("no groups yet — create one: vctl rbac group create <name>")
					}
					names := make([]string, len(groups))
					for i, g := range groups {
						names[i] = g.Name
					}
					if group, err = pickOne(names, "Select a group"); err != nil {
						return err
					}
				}
				ok, err := st.RBACGroupExists(ctx, group)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("group %q not found — create it first", group)
				}

				// 2) candidate users minus current members.
				cands, err := st.RBACCandidateUsers(ctx)
				if err != nil {
					return err
				}
				members, err := st.RBACGroupMembers(ctx, group)
				if err != nil {
					return err
				}
				inGroup := map[string]bool{}
				for _, m := range members {
					inGroup[m] = true
				}
				avail := make([]string, 0, len(cands))
				for _, u := range cands {
					if !inGroup[u] {
						avail = append(avail, u)
					}
				}
				if len(avail) == 0 {
					return fmt.Errorf("no candidate users to add — known users are already members, or nobody has used vctl yet. Add one explicitly: vctl rbac member add %s <user>", group)
				}

				// 3) multi-select and assign.
				picked, err := pickMany(avail, fmt.Sprintf("Add users to %q (space to select)", group))
				if err != nil {
					return err
				}
				if len(picked) == 0 {
					ui.Warnf(os.Stderr, "nothing selected")
					return nil
				}
				for _, u := range picked {
					if err := st.RBACMemberAdd(ctx, group, u); err != nil {
						return fmt.Errorf("add %s: %w", u, err)
					}
				}
				ui.Successf(os.Stderr, "added %d user(s) to %q: %s", len(picked), group, strings.Join(picked, ", "))
				return nil
			})
		},
	}, "admin", classAdmin)
}

func rbacGroupCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "Manage RBAC groups"}
	cmd.AddCommand(
		gate(rbacGroupListCmd(), "list", classRead),
		gate(rbacGroupShowCmd(), "list", classRead),
		gate(rbacGroupCreateCmd(), "admin", classAdmin),
		gate(rbacGroupDeleteCmd(), "admin", classAdmin),
	)
	return cmd
}

func rbacGroupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List RBAC groups",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				groups, err := st.RBACGroups(cmd.Context())
				if err != nil {
					return err
				}
				if len(groups) == 0 {
					ui.Warnf(os.Stderr, "no RBAC groups yet. Create one: vctl rbac group create <name>")
					return nil
				}
				rows := make([][]string, 0, len(groups))
				for _, g := range groups {
					rows = append(rows, []string{g.Name, fmt.Sprintf("%d", g.Members), fmt.Sprintf("%d", g.Commands), ui.Truncate(g.Description, 48)})
				}
				ui.Section(os.Stdout, "rbac groups")
				return ui.Table(os.Stdout, []string{"group", "members", "commands", "description"}, rows)
			})
		},
	}
}

func rbacGroupShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <group>",
		Short: "Show a group's members and granted commands",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				g := args[0]
				ok, err := st.RBACGroupExists(cmd.Context(), g)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("group %q not found", g)
				}
				members, err := st.RBACGroupMembers(cmd.Context(), g)
				if err != nil {
					return err
				}
				commands, err := st.RBACGroupCommands(cmd.Context(), g)
				if err != nil {
					return err
				}
				ui.Section(os.Stdout, "group "+g)
				fmt.Fprintf(os.Stdout, "members:  %s\n", joinOrDash(members))
				fmt.Fprintf(os.Stdout, "commands: %s\n", joinOrDash(commands))
				return nil
			})
		},
	}
}

func rbacGroupCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <group> [description...]",
		Short: "Create (or update) an RBAC group",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				name := args[0]
				desc := strings.Join(args[1:], " ")
				if err := st.RBACGroupUpsert(cmd.Context(), name, desc); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "group %q ready", name)
				return nil
			})
		},
	}
}

func rbacGroupDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <group>",
		Short: "Delete an RBAC group (members/grants cascade)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.RBACGroupDelete(cmd.Context(), args[0]); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "group %q deleted", args[0])
				return nil
			})
		},
	}
}

func rbacMemberCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "member", Short: "Manage group membership"}
	cmd.AddCommand(
		gate(rbacMemberAddCmd(), "admin", classAdmin),
		gate(rbacMemberRemoveCmd(), "admin", classAdmin),
	)
	return cmd
}

func rbacMemberAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <group> <user>",
		Short: "Add a user to a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				ok, err := st.RBACGroupExists(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("group %q not found — create it first", args[0])
				}
				if err := st.RBACMemberAdd(cmd.Context(), args[0], args[1]); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "%q added to %q", args[1], args[0])
				return nil
			})
		},
	}
}

func rbacMemberRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <group> <user>",
		Short: "Remove a user from a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.RBACMemberRemove(cmd.Context(), args[0], args[1]); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "%q removed from %q", args[1], args[0])
				return nil
			})
		},
	}
}

// grantableList is the multi-select menu for command grants: every gated
// command plus "*" (all), sorted.
func grantableList() []string {
	return append([]string{"*"}, sortedKeys(boolSet(gatedCommands))...)
}

func boolSet(m map[string]string) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func rbacGrantCmd() *cobra.Command {
	return gate(&cobra.Command{
		Use:   "grant [group] [command]",
		Short: "Grant command(s) to a group; with no command, pick interactively",
		Args:  cobra.RangeArgs(0, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return withStore(ctx, true, func(_ *app.App, st *store.Store) error {
				// 1) group: arg or picker.
				group := ""
				if len(args) >= 1 {
					group = args[0]
				} else {
					groups, err := st.RBACGroups(ctx)
					if err != nil {
						return err
					}
					if len(groups) == 0 {
						return fmt.Errorf("no groups yet — create one: vctl rbac group create <name>")
					}
					names := make([]string, len(groups))
					for i, g := range groups {
						names[i] = g.Name
					}
					if group, err = pickOne(names, "Select a group"); err != nil {
						return err
					}
				}
				ok, err := st.RBACGroupExists(ctx, group)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("group %q not found — create it first", group)
				}

				// 2) command(s): arg or multi-select picker.
				var commands []string
				if len(args) == 2 {
					c := args[1]
					if c != "*" {
						if _, known := gatedCommands[c]; !known {
							return fmt.Errorf("unknown command %q. Grantable: %s, or '*'", c, knownCommands())
						}
					}
					commands = []string{c}
				} else {
					picked, err := pickMany(grantableList(), fmt.Sprintf("Grant commands to %q (space to select)", group))
					if err != nil {
						return err
					}
					if len(picked) == 0 {
						ui.Warnf(os.Stderr, "nothing selected")
						return nil
					}
					commands = picked
				}

				for _, c := range commands {
					if err := st.RBACGrant(ctx, group, c); err != nil {
						return fmt.Errorf("grant %s: %w", c, err)
					}
				}
				ui.Successf(os.Stderr, "granted [%s] to %q", strings.Join(commands, ", "), group)
				return nil
			})
		},
	}, "admin", classAdmin)
}

func rbacRevokeCmd() *cobra.Command {
	return gate(&cobra.Command{
		Use:   "revoke <group> <command>",
		Short: "Revoke a command grant from a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.RBACRevoke(cmd.Context(), args[0], args[1]); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "revoked %q from %q", args[1], args[0])
				return nil
			})
		},
	}, "admin", classAdmin)
}

func rbacWhoamiCmd() *cobra.Command {
	return gate(&cobra.Command{
		Use:   "whoami",
		Short: "Show your identity, admin status, groups, and effective commands",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return withStore(ctx, false, func(a *app.App, st *store.Store) error {
				user := a.Vault.Identity(ctx)
				pols, _ := a.Vault.TokenPolicies(ctx)
				isAdmin := hasAdminPolicy(pols)
				groups, err := st.RBACGroupsForUser(ctx, user)
				if err != nil && !isUninitializedRBAC(err) {
					return err
				}
				cmds, err := st.RBACCommandsForUser(ctx, user)
				if err != nil && !isUninitializedRBAC(err) {
					return err
				}
				ui.Section(os.Stdout, "rbac whoami")
				fmt.Fprintf(os.Stdout, "identity: %s\n", dashIfEmpty(user))
				if isAdmin {
					fmt.Fprintf(os.Stdout, "admin:    %s (vctl-admin/sre-admin — bypasses command RBAC)\n", ui.OK("yes"))
				} else {
					fmt.Fprintf(os.Stdout, "admin:    no\n")
				}
				fmt.Fprintf(os.Stdout, "groups:   %s\n", joinOrDash(groups))
				fmt.Fprintf(os.Stdout, "granted:  %s\n", joinOrDash(sortedKeys(cmds)))
				return nil
			})
		},
	}, "whoami", classRead)
}

func rbacCheckCmd() *cobra.Command {
	return gate(&cobra.Command{
		Use:   "check <command>",
		Short: "Check whether you may run a command",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return withStore(ctx, false, func(a *app.App, st *store.Store) error {
				want := args[0]
				pols, _ := a.Vault.TokenPolicies(ctx)
				if hasAdminPolicy(pols) {
					fmt.Fprintf(os.Stdout, "%s %q (admin bypass)\n", ui.OK("allow"), want)
					return nil
				}
				if gatedCommands[want] == classRead {
					fmt.Fprintf(os.Stdout, "%s %q (read — default allow)\n", ui.OK("allow"), want)
					return nil
				}
				cmds, err := st.RBACCommandsForUser(ctx, a.Vault.Identity(ctx))
				if err != nil {
					return err
				}
				if cmds["*"] || cmds[want] {
					fmt.Fprintf(os.Stdout, "%s %q (granted)\n", ui.OK("allow"), want)
				} else {
					fmt.Fprintf(os.Stdout, "%s %q (no grant)\n", ui.Fail("deny"), want)
				}
				return nil
			})
		},
	}, "check", classRead)
}

func knownCommands() string {
	out := make([]string, 0, len(gatedCommands))
	for c := range gatedCommands {
		out = append(out, c)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinOrDash(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return strings.Join(ss, ", ")
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
