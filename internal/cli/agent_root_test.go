package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// The agent tree is defined by what is absent: the split exists so a fleet
// host does not carry operator commands. The Vault policy already made them
// inert there; this pins the least-functionality half of the argument.
func TestAgentTreeCarriesNoOperatorCommands(t *testing.T) {
	root := NewAgentRoot(fakeDeps(t))

	for _, want := range []string{"node-agent", "collect", "watch-sessions", "session-start", "openstack"} {
		if findCmd(root, want) == nil {
			t.Errorf("agent tree is missing %q — a unit on the fleet invokes it", want)
		}
	}
	if os := findCmd(root, "openstack"); os != nil {
		names := make([]string, 0, 2)
		for _, c := range os.Commands() {
			names = append(names, c.Name())
		}
		if len(names) != 1 || names[0] != "reconcile" {
			t.Errorf("agent openstack subtree = %v, want exactly [reconcile]", names)
		}
	}

	for _, banned := range []string{"ssh", "exec", "list", "edit", "delete", "add", "rbac", "mcp", "sync", "wg", "ip", "audit", "session", "login", "migrate", "retention"} {
		if findCmd(root, banned) != nil {
			t.Errorf("operator command %q is in the agent tree; the split exists to keep it off the fleet", banned)
		}
	}
}

// The agent root installs no RBAC hook — nothing in its tree is gated, and
// the agents are authorized by the host AppRole's Vault policy. That is only
// safe while it stays true: a gated command added here would carry its
// annotation and nothing would enforce it.
func TestAgentTreeCarriesNoGates(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if name := c.Annotations["rbac.command"]; name != "" {
			t.Errorf("%s is gated as %q, but the agent root runs no RBAC hook — move it or gate the agent tree", c.CommandPath(), name)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(NewAgentRoot(fakeDeps(t)))
}
