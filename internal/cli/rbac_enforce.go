package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// PostgreSQL command grants are an additional client policy. Vault policies are
// the authoritative boundary for SSH signing, audit reads, and database roles.
const (
	classRead   = "read"
	classMutate = "mutate"
	classAdmin  = "admin"
)

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

func gate(cmd *cobra.Command, name, class string) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations["rbac.command"] = name
	cmd.Annotations["rbac.class"] = class
	return cmd
}

func hasAdminPolicy(pols []string) bool {
	return slices.Contains(pols, "vctl-admin") || slices.Contains(pols, "sre-admin")
}

func isUninitializedRBAC(err error) bool {
	return err != nil && strings.Contains(err.Error(), "42P01")
}

func enforceRBAC(cmd *cobra.Command) error {
	name := cmd.Annotations["rbac.command"]
	if name == "" {
		return nil
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
	pols, err := a.Vault.TokenPolicies(ctx)
	if err != nil {
		return fmt.Errorf("rbac: token lookup: %w", err)
	}
	if hasAdminPolicy(pols) {
		return nil
	}
	if class == classRead {
		return nil
	}
	if class == classAdmin {
		return fmt.Errorf("rbac: '%s' is admin-only (needs vctl-admin or sre-admin)", name)
	}

	user := a.Vault.Identity(ctx)
	if user == "" {
		return fmt.Errorf("rbac: cannot determine your identity — run 'vctl login'")
	}
	st, err := a.OpenStore(ctx, false)
	if err != nil {
		return err
	}
	defer st.Close()
	commands, err := st.RBACCommandsForUser(ctx, user)
	if err != nil {
		if isUninitializedRBAC(err) {
			return fmt.Errorf("rbac: not initialized yet — an admin must run 'vctl sync --migrate' first")
		}
		return err
	}
	if commands["*"] || commands[name] {
		return nil
	}
	return fmt.Errorf("rbac: '%s' not permitted for %q — ask an admin to grant it:\n  vctl rbac grant <group> %s", name, user, name)
}
