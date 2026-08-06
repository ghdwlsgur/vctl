package cli

import (
	"github.com/spf13/cobra"
	"strings"
	"testing"
)

// A farm with sixty confirmed hosts should not print sixty names to say it
// agreed.
func TestCountAndNamesAFewAndCountsTheRest(t *testing.T) {
	many := []string{"a", "b", "c", "d", "e", "f"}
	got := countAnd(many)

	if !strings.HasPrefix(got, "6 · ") {
		t.Errorf("countAnd = %q, want the count first", got)
	}
	if !strings.Contains(got, "+2 more") {
		t.Errorf("countAnd = %q, want the remainder counted rather than listed", got)
	}
	if got := countAnd(nil); got != "none" {
		t.Errorf("countAnd(nil) = %q", got)
	}
}

// A colon in a Vault path is legal but awkward everywhere it is then typed.
// The port still has to survive: two deployments can share an address.
func TestVaultFarmKeyIsTypeableAndKeepsThePort(t *testing.T) {
	got := vaultFarmKey("172.16.0.245:5000")
	// kv/teams/sre is shared with everything else the team stores there.
	if !strings.HasPrefix(got, "vctl-") {
		t.Errorf("key = %q, want the vctl- prefix that keeps these apart", got)
	}
	if strings.Contains(got, ":") {
		t.Errorf("key = %q, still carries a colon", got)
	}
	if !strings.Contains(got, "5000") {
		t.Errorf("key = %q, lost the port — two deployments can share an address", got)
	}
	if vaultFarmKey("10.0.0.1:5000") == vaultFarmKey("10.0.0.1:5001") {
		t.Error("two ports on one address collapsed into one key")
	}
}

// reconcile must not be app-gated. A CronJob authenticating with kubernetes
// auth has no per-person identity, and the gate opened the inventory with
// vctl-ro — a role this workload has no reason to hold. It failed before the
// command it guards could run:
//
//	rbac: 'openstack-reconcile' needs the inventory database and it is
//	unreachable: database/creds/vctl-ro: permission denied
//
// Vault is the boundary instead: kv/teams/sre/vctl-* and database/creds/vctl-rw.
func TestReconcileIsNotAppGated(t *testing.T) {
	var found *cobra.Command
	for _, c := range openstackCmd().Commands() {
		if c.Name() == "reconcile" {
			found = c
		}
	}
	if found == nil {
		t.Fatal("reconcile is not registered under openstack")
	}
	if name := found.Annotations["rbac.command"]; name != "" {
		t.Errorf("reconcile carries the rbac annotation %q; the gate needs an identity a CronJob does not have", name)
	}
}

// --self exists so a unit file does not carry the farm's name. A host moved
// between deployments, or a farm whose Keystone VIP changes, would otherwise
// leave a stale identifier in a systemd unit nobody looks at.
func TestSelfFindsTheHostsOwnFarm(t *testing.T) {
	farms := map[string][]string{
		"172.16.0.245:5000": {"sre-srv-0050", "sre-srv-0059"},
		"172.16.0.10:5000":  {"incheon-aio01"},
	}
	got, err := farmOfHost(farms, "sre-srv-0059")
	if err != nil {
		t.Fatalf("farmOfHost: %v", err)
	}
	if got != "172.16.0.245:5000" {
		t.Errorf("farm = %q, want the one this host belongs to", got)
	}
}

// A host no probe has placed in a deployment has nothing to reconcile, and must
// say so rather than silently doing every farm — which is what an empty --farm
// would have meant.
func TestSelfRefusesWhenTheHostBelongsToNoFarm(t *testing.T) {
	farms := map[string][]string{"172.16.0.245:5000": {"sre-srv-0050"}}

	if _, err := farmOfHost(farms, "some-other-host"); err == nil {
		t.Fatal("a host in no deployment was accepted; it would have reconciled every farm")
	}
}

// The inventory name is not always the os hostname — one host here reports as
// k8s-all-01 while the inventory calls it sre-srv-0023.
func TestSelfAcceptsAnOverriddenHostname(t *testing.T) {
	farms := map[string][]string{"172.16.0.245:5000": {"sre-srv-0023"}}

	got, err := farmOfHost(farms, "sre-srv-0023")
	if err != nil || got != "172.16.0.245:5000" {
		t.Errorf("farmOfHost with an overridden name = %q, %v", got, err)
	}
}
