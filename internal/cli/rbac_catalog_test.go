package cli

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/authz"
)

// The authz catalog and the command tree must agree in both directions.
//
// A gate whose name the catalog does not know is a mutate command nobody can
// grant except through "*" or an admin policy — `vctl rbac grant <group> edit`
// failed with "unknown command" while the edit gate demanded exactly that
// grant. The reverse is a catalog entry describing a gate that does not
// exist, which `rbac check` then answers for as if it did. Both happened;
// this walk is what keeps either from coming back.
func TestEveryGateMatchesTheCatalog(t *testing.T) {
	seen := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if name := c.Annotations["rbac.command"]; name != "" {
			class, ok := authz.ClassOf(name)
			if !ok {
				t.Errorf("%s: gated as %q, which is not in the authz catalog", c.CommandPath(), name)
			} else {
				seen[name] = true
				got := c.Annotations["rbac.class"]
				// A gate carries the catalog's class, or read — the read view
				// of a resource whose grant name is mutate-classed
				// (gateReadView; `vctl ip` listing the ledger `ip set` writes).
				if got != string(class) && got != string(authz.ClassRead) {
					t.Errorf("%s: gated %q as %s; the catalog says %s", c.CommandPath(), name, got, class)
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(NewRoot(fakeDeps(t)))

	for _, name := range authz.GatedCommands() {
		if !seen[name] {
			t.Errorf("catalog entry %q gates nothing in the command tree", name)
		}
	}
}
