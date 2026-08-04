package probes

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeHost answers the commands a probe runs, so the probe can be exercised
// against a shaped machine instead of whatever the test runner happens to be.
type fakeHost struct {
	// systemd maps a unit name to what `systemctl is-active` says.
	systemd map[string]string
	// containers maps a container name to its state, as podman/docker report.
	containers map[string]string
	// versions maps a binary name to its version banner.
	versions map[string]string
	calls    []string
}

func (f *fakeHost) probe() *OpenStack {
	return &OpenStack{root: "/nonexistent", run: f.run}
}

func (f *fakeHost) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "systemctl":
		// `systemctl show -p LoadState -p ActiveState --value <unit>` prints one
		// value per line. A unit that does not exist is "not-found", which is
		// the distinction `is-active` cannot make — it says "inactive" either way.
		unit := strings.TrimSuffix(args[len(args)-1], ".service")
		if s, ok := f.systemd[unit]; ok {
			return []byte("loaded\n" + s + "\n"), nil
		}
		return []byte("not-found\ninactive\n"), nil
	case "podman", "docker":
		if len(args) > 0 && args[0] == "exec" {
			if v, ok := f.versions[args[len(args)-2]]; ok {
				return []byte(v), nil
			}
			return nil, errors.New("no such container")
		}
		for _, a := range args {
			if !strings.HasPrefix(a, "name=^") {
				continue
			}
			n := strings.TrimSuffix(strings.TrimPrefix(a, "name=^"), "$")
			if st, ok := f.containers[n]; ok {
				return []byte(n + " " + st + "\n"), nil
			}
		}
		return []byte(""), nil
	default:
		if v, ok := f.versions[name]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("not found")
	}
}

// A running nova-compute is what makes a host a compute node.
func TestOpenStackDetectsAComputeNode(t *testing.T) {
	h := &fakeHost{
		systemd:  map[string]string{"nova-compute": "active"},
		versions: map[string]string{"nova-compute": "31.2.0\n", "libvirtd": "libvirtd (libvirt) 10.0.0\n"},
	}
	res := h.probe().Collect(context.Background())

	if res.Err != nil {
		t.Fatalf("probe errored: %v", res.Err)
	}
	if !res.Detected {
		t.Error("a host running nova-compute was not detected")
	}
	if !slices.Contains(res.Roles, "compute") {
		t.Errorf("roles = %v, want compute", res.Roles)
	}
	if got := res.Components["nova-compute"].Version; got != "31.2.0" {
		t.Errorf("nova-compute version = %q, want 31.2.0", got)
	}
	if got := res.Components["libvirt"].Version; got != "10.0.0" {
		t.Errorf("libvirt version = %q; hypervisor facts belong to a compute node", got)
	}
}

// A workstation with the client package installed is not part of the fleet.
// Counting it would put machines that run nothing into capacity planning.
func TestOpenStackIgnoresAHostWithNoServices(t *testing.T) {
	h := &fakeHost{
		// The client binary exists and answers --version. That is all.
		versions: map[string]string{"openstack": "openstack 7.1.0\n"},
	}
	res := h.probe().Collect(context.Background())

	if res.Detected {
		t.Errorf("a host with only client tooling was detected: %+v", res.Components)
	}
	if len(res.Roles) != 0 {
		t.Errorf("roles = %v, want none", res.Roles)
	}
}

// Kolla runs every service as a container and leaves no systemd unit, so a
// systemd-only probe reports a full controller as an empty host.
func TestOpenStackFindsKollaContainers(t *testing.T) {
	h := &fakeHost{
		containers: map[string]string{
			"nova-conductor":   "running",
			"nova-scheduler":   "running",
			"neutron-l3-agent": "running",
		},
	}
	res := h.probe().Collect(context.Background())

	if !res.Detected {
		t.Fatal("a Kolla controller was not detected")
	}
	for _, want := range []string{"controller", "network"} {
		if !slices.Contains(res.Roles, want) {
			t.Errorf("roles = %v, want %s", res.Roles, want)
		}
	}
}

// A stopped service is a component that is down, not an absent one. Reporting
// it as absent would make a broken compute node look like a host that never
// had OpenStack.
func TestOpenStackReportsAStoppedServiceWithoutClaimingTheRole(t *testing.T) {
	h := &fakeHost{systemd: map[string]string{"nova-compute": "failed"}}
	res := h.probe().Collect(context.Background())

	if !res.Detected {
		t.Error("a host with a failed nova-compute was reported as having no OpenStack")
	}
	if _, ok := res.Components["nova-compute"]; !ok {
		t.Error("the stopped service was not reported at all")
	}
	if res.Components["nova-compute"].Active {
		t.Error("a failed service was reported as active")
	}
	if slices.Contains(res.Roles, "compute") {
		t.Error("a host whose nova-compute is down was still claimed as a compute node")
	}
}

// The probe must not decide which deployment a host belongs to. Local evidence
// cannot separate two farms behind one endpoint, and a guess rendered as a fact
// is the failure this whole design avoids.
func TestOpenStackDoesNotGuessTheDeployment(t *testing.T) {
	h := &fakeHost{systemd: map[string]string{"nova-compute": "active"}}
	res := h.probe().Collect(context.Background())

	if got := res.Details["deployment"]; got != "unknown" {
		t.Errorf("deployment = %q, want unknown — the host cannot know this", got)
	}
	if _, ok := res.Details["deployment_source"]; ok {
		t.Error("a deployment source was claimed with nothing declaring one")
	}
}

// Several roles on one host is normal in a small deployment, and the model has
// to carry all of them.
func TestOpenStackReportsEveryRoleAHostHolds(t *testing.T) {
	h := &fakeHost{systemd: map[string]string{
		"nova-conductor":   "active",
		"neutron-l3-agent": "active",
		"cinder-volume":    "active",
	}}
	res := h.probe().Collect(context.Background())

	for _, want := range []string{"block-storage", "controller", "network"} {
		if !slices.Contains(res.Roles, want) {
			t.Errorf("roles = %v, missing %s", res.Roles, want)
		}
	}
	// Sorted, so the stored rows and the listing do not reorder between runs.
	if !slices.IsSorted(res.Roles) {
		t.Errorf("roles = %v, want a stable order", res.Roles)
	}
}
