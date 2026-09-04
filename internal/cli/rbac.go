package cli

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/authz"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func rbacCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rbac",
		Short: "Manage app-layer command RBAC (groups, members, grants)",
		Long: `rbac manages the fine-grained, admin-managed command permissions (layer 2).

Vault policies are the authoritative capability boundary. On top of that,
admins group users and grant them specific CLI commands here. Read commands
are allowed to any authenticated user by default; mutate commands (ssh, exec,
sync, add/edit/delete, ip, wg-sync, openstack-farm, trust-ca) need a group
grant. Admins (the configured admin_policies) bypass.`,
	}
	cmd.AddCommand(rbacAssignCmd(env), rbacGroupCmd(env), rbacMemberCmd(env), rbacGrantCmd(env), rbacRevokeCmd(env), rbacUsersCmd(env), rbacWhoamiCmd(env), rbacCheckCmd(env))
	return cmd
}

// rbacUsersCmd lists everyone who has logged in, with the vctl version they last
// used and when — so an admin can see who is behind. Read (default-allow).
func rbacUsersCmd(env cmdkit.Env) *cobra.Command {
	return cmdkit.Gate(&cobra.Command{
		Use:   "users",
		Short: "List known users with their vctl version and last login",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				users, err := st.SeenUsers(cmd.Context())
				if err != nil {
					if authz.IsUninitializedRBAC(err) {
						return fmt.Errorf("rbac: not initialized yet — an admin must run 'vctl sync --migrate' first")
					}
					return err
				}
				if len(users) == 0 {
					ui.Warnf(os.Stderr, "no users recorded yet (they appear after `vctl login`)")
					return nil
				}
				rows := make([][]string, 0, len(users))
				for _, u := range users {
					ver := u.Version
					if ver == "" {
						ver = ui.Muted("-")
					}
					rows = append(rows, []string{u.Username, ver, "seen " + strutil.CompactDuration(time.Since(u.LastSeen))})
				}
				ui.Section(os.Stdout, "rbac users")
				return ui.Table(os.Stdout, []string{"user", "vctl version", "last login"}, rows)
			})
		},
	}, "users")
}

// rbacAssignCmd is the convenient interactive assigner. Admin-only.
func rbacAssignCmd(env cmdkit.Env) *cobra.Command {
	return cmdkit.Gate(&cobra.Command{
		Use:   "assign [group]",
		Short: "Interactively add users to a group (pick group → select users)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return env.WithStore(ctx, true, func(_ *app.App, st *store.Store) error {
				return runRBACAssign(ctx, st, args)
			})
		},
	}, "admin")
}

// resolveRBACGroup is the group an rbac command acts on: the first argument
// when one was given, otherwise picked from the list — and in either case one
// that exists, because every caller's next step is a write against it.
func resolveRBACGroup(ctx context.Context, st *store.Store, args []string) (string, error) {
	group := ""
	if len(args) >= 1 {
		group = args[0]
	} else {
		groups, err := st.RBACGroups(ctx)
		if err != nil {
			return "", err
		}
		if len(groups) == 0 {
			return "", fmt.Errorf("no groups yet — create one: vctl rbac group create <name>")
		}
		names := make([]string, len(groups))
		for i, g := range groups {
			names[i] = g.Name
		}
		if group, err = cmdkit.PickOne(names, "Select a group"); err != nil {
			return "", err
		}
	}
	ok, err := st.RBACGroupExists(ctx, group)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("group %q not found — create it first", group)
	}
	return group, nil
}

// runRBACAssign picks a group, then multi-selects users to add as members.
// Candidate users come from seen_users + existing members (RBACCandidateUsers).
func runRBACAssign(ctx context.Context, st *store.Store, args []string) error {
	// 1) group: arg, or pick from the list.
	group, err := resolveRBACGroup(ctx, st, args)
	if err != nil {
		return err
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
	picked, err := cmdkit.PickMany(avail, fmt.Sprintf("Add users to %q (space to select)", group))
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
}

func rbacGroupCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{Use: "group", Short: "Manage RBAC groups"}
	cmd.AddCommand(
		cmdkit.Gate(rbacGroupListCmd(env), "list"),
		cmdkit.Gate(rbacGroupShowCmd(env), "list"),
		cmdkit.Gate(rbacGroupCreateCmd(env), "admin"),
		cmdkit.Gate(rbacGroupDeleteCmd(env), "admin"),
	)
	return cmd
}

func rbacGroupListCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List RBAC groups",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
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

func rbacGroupShowCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "show <group>",
		Short: "Show a group's members and granted commands",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
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

func rbacGroupCreateCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "create <group> [description...]",
		Short: "Create (or update) an RBAC group",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
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

func rbacGroupDeleteCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <group>",
		Short: "Delete an RBAC group (members/grants cascade)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.RBACGroupDelete(cmd.Context(), args[0]); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "group %q deleted", args[0])
				return nil
			})
		},
	}
}

func rbacMemberCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{Use: "member", Short: "Manage group membership"}
	cmd.AddCommand(
		cmdkit.Gate(rbacMemberAddCmd(env), "admin"),
		cmdkit.Gate(rbacMemberRemoveCmd(env), "admin"),
	)
	return cmd
}

func rbacMemberAddCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "add <group> <user>",
		Short: "Add a user to a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
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

func rbacMemberRemoveCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <group> <user>",
		Short: "Remove a user from a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.RBACMemberRemove(cmd.Context(), args[0], args[1]); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "%q removed from %q", args[1], args[0])
				return nil
			})
		},
	}
}

// grantableList is the multi-select menu for command grants: every grantable
// (mutate) command plus "*" (all), sorted.
func grantableList() []string {
	return authz.Grantable()
}

func rbacGrantCmd(env cmdkit.Env) *cobra.Command {
	return cmdkit.Gate(&cobra.Command{
		Use:   "grant [group] [command]",
		Short: "Grant command(s) to a group; with no command, pick interactively",
		Args:  cobra.RangeArgs(0, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return env.WithStore(ctx, true, func(_ *app.App, st *store.Store) error {
				return runRBACGrant(ctx, st, args)
			})
		},
	}, "admin")
}

// runRBACGrant resolves the group (arg or picker) and the command(s) (arg or
// multi-select picker), then records one grant per command.
func runRBACGrant(ctx context.Context, st *store.Store, args []string) error {
	// 1) group: arg or picker.
	group, err := resolveRBACGroup(ctx, st, args)
	if err != nil {
		return err
	}

	// 2) command(s): arg or multi-select picker.
	var commands []string
	if len(args) == 2 {
		c := args[1]
		if c != "*" {
			// Only mutate commands take grants: read is default-allowed
			// to any authenticated user and admin follows the Vault
			// policy, so granting either records a row that changes
			// nothing — and reads as if it had.
			if class, known := authz.ClassOf(c); !known || class != authz.ClassMutate {
				return fmt.Errorf("cannot grant %q. Grantable: %s, or '*'", c, knownCommands())
			}
		}
		commands = []string{c}
	} else {
		picked, err := cmdkit.PickMany(grantableList(), fmt.Sprintf("Grant commands to %q (space to select)", group))
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
}

func rbacRevokeCmd(env cmdkit.Env) *cobra.Command {
	return cmdkit.Gate(&cobra.Command{
		Use:   "revoke <group> <command>",
		Short: "Revoke a command grant from a group",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithStore(cmd.Context(), true, func(_ *app.App, st *store.Store) error {
				if err := st.RBACRevoke(cmd.Context(), args[0], args[1]); err != nil {
					return err
				}
				ui.Successf(os.Stderr, "revoked %q from %q", args[1], args[0])
				return nil
			})
		},
	}, "admin")
}

func rbacWhoamiCmd(env cmdkit.Env) *cobra.Command {
	return cmdkit.Gate(&cobra.Command{
		Use:   "whoami",
		Short: "Show your identity, admin status, groups, and effective commands",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			return env.WithStore(ctx, false, func(a *app.App, st *store.Store) error {
				info, err := a.Vault.LookupToken(ctx)
				if err != nil {
					return err
				}
				user := info.Identity
				isAdmin := authz.HasAdminPolicy(info.Policies, a.Cfg.AdminPolicies)
				groups, err := st.RBACGroupsForUser(ctx, user)
				if err != nil && !authz.IsUninitializedRBAC(err) {
					return err
				}
				cmds, err := st.RBACCommandsForUser(ctx, user)
				if err != nil && !authz.IsUninitializedRBAC(err) {
					return err
				}
				ui.Section(os.Stdout, "rbac whoami")
				fmt.Fprintf(os.Stdout, "identity: %s\n", ui.OrDash(user))
				if isAdmin {
					fmt.Fprintf(os.Stdout, "admin:    %s (%s — bypasses command RBAC)\n",
						ui.OK("yes"), strings.Join(a.Cfg.AdminPolicies, "/"))
				} else {
					fmt.Fprintf(os.Stdout, "admin:    no\n")
				}
				fmt.Fprintf(os.Stdout, "groups:   %s\n", joinOrDash(groups))
				fmt.Fprintf(os.Stdout, "granted:  %s\n", joinOrDash(slices.Sorted(maps.Keys(cmds))))
				return nil
			})
		},
	}, "whoami")
}

func rbacCheckCmd(env cmdkit.Env) *cobra.Command {
	return cmdkit.Gate(&cobra.Command{
		Use:   "check <command>",
		Short: "Check whether you may run a command",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return env.WithStore(ctx, false, func(a *app.App, st *store.Store) error {
				want := args[0]
				info, err := a.Vault.LookupToken(ctx)
				if err != nil {
					return err
				}
				if authz.HasAdminPolicy(info.Policies, a.Cfg.AdminPolicies) {
					fmt.Fprintf(os.Stdout, "%s %q (admin bypass)\n", ui.OK("allow"), want)
					return nil
				}
				// The class decides the answer, so it must come from the catalog,
				// not from guessing. An unknown name used to fall through to the
				// grant lookup and report "deny" for commands that were never
				// gated at all.
				class, isGated := authz.ClassOf(want)
				if !isGated {
					fmt.Fprintf(os.Stdout, "%s %q (not RBAC-gated)\n", ui.OK("allow"), want)
					return nil
				}
				switch class {
				case authz.ClassRead:
					fmt.Fprintf(os.Stdout, "%s %q (read — default allow)\n", ui.OK("allow"), want)
					return nil
				case authz.ClassAdmin:
					fmt.Fprintf(os.Stdout, "%s %q (admin-only — needs %s)\n",
						ui.Fail("deny"), want, strings.Join(a.Cfg.AdminPolicies, " or "))
					return nil
				}
				cmds, err := st.RBACCommandsForUser(ctx, info.Identity)
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
	}, "check")
}

func knownCommands() string {
	return strings.Join(authz.GrantableCommands(), ", ")
}

func joinOrDash(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return strings.Join(ss, ", ")
}
