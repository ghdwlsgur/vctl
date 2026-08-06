package probes

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
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

	// engineAbsent is an engine that is not installed at all — the one failure
	// that legitimately means "this host does not use containers".
	engineAbsent map[string]bool
	// engineRefuses is an engine that is installed and will not answer the
	// direct call. This is the real sandbox: `podman ps` takes a write lock on
	// the container store, and ProtectSystem=strict makes that path read-only.
	engineRefuses map[string]bool

	calls []string
}

func (f *fakeHost) probe() *OpenStack {
	return &OpenStack{root: "/nonexistent", run: f.run}
}

// probeWithSocket shapes a host that exposes a container engine socket, with
// the socket file really present under a temp root so the existence check is
// exercised rather than stubbed. list is what the socket answers.
func (f *fakeHost) probeWithSocket(t *testing.T, socket string, list func() (map[string]containerInfo, error)) *OpenStack {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(root+socket), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(root+socket, nil, 0o600); err != nil {
		t.Fatalf("write socket: %v", err)
	}
	return &OpenStack{
		root: root,
		run:  f.run,
		listSocket: func(context.Context, string) (map[string]containerInfo, error) {
			f.calls = append(f.calls, "socket "+socket)
			return list()
		},
	}
}

func (f *fakeHost) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "systemctl":
		// `systemctl show -p LoadState -p ActiveState --value u1 u2 …` prints
		// two value lines per unit, in the order given, separated by a blank
		// line — verified against systemd on a real host. A unit that does not
		// exist is "not-found", which is the distinction `is-active` cannot
		// make: it says "inactive" either way.
		var b strings.Builder
		var n int
		for _, a := range args {
			if !strings.HasSuffix(a, ".service") {
				continue
			}
			if n > 0 {
				b.WriteString("\n")
			}
			n++
			if s, ok := f.systemd[strings.TrimSuffix(a, ".service")]; ok {
				b.WriteString("loaded\n" + s + "\n")
				continue
			}
			b.WriteString("not-found\ninactive\n")
		}
		return []byte(b.String()), nil
	case "podman", "docker":
		if f.engineAbsent[name] {
			return nil, exec.ErrNotFound
		}
		if len(args) > 0 && args[0] == "exec" {
			if v, ok := f.versions[args[len(args)-2]]; ok {
				return []byte(v), nil
			}
			return nil, errors.New("no such container")
		}
		// The direct call opens the local store; --remote goes through the
		// socket and writes nothing.
		if f.engineRefuses[name] && !slices.Contains(args, "--remote") {
			return nil, errors.New("configure storage: open /var/lib/containers/storage/storage.lock: read-only file system")
		}
		// One listing for the whole pass, the way the engines are actually
		// asked. Names are whatever the test put in the map — and for Kolla
		// those are the real underscored ones.
		names := make([]string, 0, len(f.containers))
		for n := range f.containers {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			b.WriteString(n + " " + f.containers[n] + "\n")
		}
		return []byte(b.String()), nil
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

// Active is only meaningful for something that runs. qemu is exec'd per
// instance and has no daemon, so a reader that judges it by Active alone puts a
// stopped component on every healthy compute node.
func TestOpenStackMarksWhichComponentsAreServices(t *testing.T) {
	h := &fakeHost{
		systemd: map[string]string{"nova-compute": "active"},
		versions: map[string]string{
			"nova-compute":       "31.2.0\n",
			"libvirtd":           "libvirtd (libvirt) 10.0.0\n",
			"qemu-system-x86_64": "QEMU emulator version 8.2.0\n",
		},
	}
	res := h.probe().Collect(context.Background())

	for _, name := range []string{"nova-compute", "libvirt"} {
		if !res.Components[name].Service {
			t.Errorf("%s was not marked as a service, so its run state cannot be read", name)
		}
	}
	if qemu := res.Components["qemu"]; qemu.Service {
		t.Errorf("qemu was marked as a service; it has a version (%s) and no daemon", qemu.Version)
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
//
// The names here are the ones a real Kolla controller answers with — taken off
// incheon-aio01, not invented. The previous version of this test used
// hyphenated names, which no Kolla host has ever used, so it agreed with the
// bug it was meant to catch: the probe filtered on `nova-conductor`, matched
// nothing, and reported a full controller as a host with no OpenStack on it.
func TestOpenStackFindsKollaContainers(t *testing.T) {
	h := &fakeHost{
		containers: map[string]string{
			"nova_api":       "running",
			"nova_conductor": "running",
			"nova_scheduler": "running",
			"keystone":       "running",
			"glance_api":     "running",
			"placement_api":  "running",
			"cinder_volume":  "running",
			"neutron_server": "running",
			"ovn_northd":     "running",
			"horizon":        "running",
		},
	}
	res := h.probe().Collect(context.Background())

	if !res.Detected {
		t.Fatal("a Kolla controller was not detected")
	}
	for _, want := range []string{"block-storage", "controller", "dashboard", "identity", "image", "network"} {
		if !slices.Contains(res.Roles, want) {
			t.Errorf("roles = %v, missing %s", res.Roles, want)
		}
	}
	if _, ok := res.Components["nova-conductor"]; !ok {
		t.Error("the container was found but not reported under its service name")
	}
}

// A Kolla compute node, as gpu01 actually reports. OVN puts ovn-controller on
// every hypervisor, so counting it as networking would label the whole compute
// fleet as network nodes.
func TestOpenStackKollaComputeIsNotANetworkNode(t *testing.T) {
	h := &fakeHost{
		containers: map[string]string{
			"nova_compute":               "running",
			"nova_libvirt":               "running",
			"ovn_controller":             "running",
			"neutron_ovn_metadata_agent": "running",
		},
	}
	res := h.probe().Collect(context.Background())

	if !slices.Contains(res.Roles, "compute") {
		t.Errorf("roles = %v, want compute", res.Roles)
	}
	if slices.Contains(res.Roles, "network") {
		t.Errorf("roles = %v — ovn-controller runs on every hypervisor and is not a network role", res.Roles)
	}
	// Still worth reporting: it says what the host is running even though it
	// names no role of its own.
	if _, ok := res.Components["ovn-controller"]; !ok {
		t.Error("ovn-controller was not reported as a component")
	}
}

// The listing is asked for once per pass, not once per service. Under the
// agent's CPUQuota=2% a fork per service was ~50 of them a pass.
func TestOpenStackListsContainersOncePerEngine(t *testing.T) {
	h := &fakeHost{containers: map[string]string{"nova_compute": "running"}}
	h.probe().Collect(context.Background())

	var listings int
	for _, c := range h.calls {
		if strings.HasPrefix(c, "podman ps") || strings.HasPrefix(c, "docker ps") {
			listings++
		}
	}
	if listings > 2 {
		t.Errorf("%d container listings for %d services; want one per engine", listings, len(osServices))
	}
}

// A stopped service is a component that is down, not an absent one, and the
// host is still built to do the job.
//
// Roles used to require a running service, which made the topology shrink
// during an outage: a compute node whose nova-compute is down dropped out of
// the compute count at exactly the moment somebody was looking because
// something broke. The role is what is deployed; ActiveRoles is what is up.
func TestOpenStackKeepsTheRoleWhenTheServiceIsDown(t *testing.T) {
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
	if !slices.Contains(res.Roles, "compute") {
		t.Errorf("roles = %v — a compute node whose nova-compute is down is still a compute node", res.Roles)
	}
	if slices.Contains(res.ActiveRoles, "compute") {
		t.Errorf("active roles = %v — nothing is running the role", res.ActiveRoles)
	}
}

// With everything up the two lists agree, and the difference between them is
// exactly the outage.
func TestOpenStackActiveRolesMatchRolesWhenNothingIsDown(t *testing.T) {
	h := &fakeHost{systemd: map[string]string{
		"nova-compute":   "active",
		"nova-conductor": "failed",
	}}
	res := h.probe().Collect(context.Background())

	if !slices.Contains(res.Roles, "compute") || !slices.Contains(res.Roles, "controller") {
		t.Errorf("roles = %v, want both deployed roles", res.Roles)
	}
	if !slices.Contains(res.ActiveRoles, "compute") {
		t.Errorf("active roles = %v, want the running one", res.ActiveRoles)
	}
	if slices.Contains(res.ActiveRoles, "controller") {
		t.Errorf("active roles = %v — nova-conductor is failed", res.ActiveRoles)
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

// The engine is asked over its socket, never by running its CLI.
//
// The CLI was the first implementation and cannot work here. This agent's unit
// is sized for a heartbeat — MemoryMax=48M, TasksMax=24, CPUQuota=2% — and a
// container engine is a large Go program that inherits all of it. On a real
// controller both engines aborted:
//
//	could not list containers (podman: signal: aborted (core dumped);
//	docker: signal: aborted (core dumped))
//
// Widening the unit on every OpenStack host was the alternative. The socket
// costs no subprocess at all, so the narrow unit stays narrow.
func TestOpenStackAsksTheSocketAndNeverForksTheEngine(t *testing.T) {
	h := &fakeHost{}
	p := h.probeWithSocket(t, "/run/podman/podman.sock", func() (map[string]containerInfo, error) {
		return map[string]containerInfo{"nova_compute": {
			State: "running",
			Image: "172.16.0.11:7777/openstack.kolla/nova-compute:2025.1-rocky-9",
		}}, nil
	})
	res := p.Collect(context.Background())

	if res.Err != nil {
		t.Fatalf("probe errored: %v", res.Err)
	}
	if !slices.Contains(res.Roles, "compute") {
		t.Errorf("roles = %v, want compute via the socket", res.Roles)
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "podman ") || strings.HasPrefix(c, "docker ") {
			t.Errorf("the engine CLI was run (%q); it aborts inside this agent's cgroup", c)
		}
	}
}

// A host that exposes a socket and refuses on it must not fall back to forking
// the CLI: the CLI is what cannot run here, so the fallback would turn a
// reportable failure into a crash.
func TestOpenStackDoesNotForkTheCLIWhenASocketRefuses(t *testing.T) {
	h := &fakeHost{}
	p := h.probeWithSocket(t, "/run/podman/podman.sock", func() (map[string]containerInfo, error) {
		return nil, errors.New("connection refused")
	})
	res := p.Collect(context.Background())

	if res.Err == nil {
		t.Fatal("a refused socket was reported as a successful probe")
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "podman ") || strings.HasPrefix(c, "docker ") {
			t.Errorf("fell back to the engine CLI (%q) after the socket refused", c)
		}
	}
}

// This is the failure that made a full Kolla controller report "probed, none
// found": the listing was refused, the error was swallowed, and an empty map
// became an answer. An engine that is installed and will not answer means the
// probe could not look, and it has to say so.
func TestOpenStackRefusesToAnswerWhenTheListingFails(t *testing.T) {
	h := &fakeHost{containers: map[string]string{"nova_compute": "running"}}
	// Installed, and refusing every way of being asked — the direct call and
	// the socket both.
	p := &OpenStack{root: "/nonexistent", run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "podman" || name == "docker" {
			return nil, errors.New("permission denied")
		}
		return h.run(ctx, name, args...)
	}}
	res := p.Collect(context.Background())

	if res.Err == nil {
		t.Fatal("a refused listing was reported as a successful probe")
	}
	if res.Detected {
		t.Error("a probe that could not look claimed to have found something")
	}
	if len(res.Roles) != 0 {
		t.Errorf("roles = %v, want none — nothing was established", res.Roles)
	}
}

// Most of the fleet has no container engine at all. That is an answer, not a
// failure, and turning it into one would put every plain server into the
// "could not be probed" column.
func TestOpenStackTreatsAMissingEngineAsAnAnswer(t *testing.T) {
	h := &fakeHost{
		engineAbsent: map[string]bool{"podman": true, "docker": true},
		systemd:      map[string]string{"nova-compute": "active"},
	}
	res := h.probe().Collect(context.Background())

	if res.Err != nil {
		t.Fatalf("a host with no container engine was reported as a probe failure: %v", res.Err)
	}
	if !slices.Contains(res.Roles, "compute") {
		t.Errorf("roles = %v — the systemd answer was lost", res.Roles)
	}
}

// One systemctl call for every unit, not one per unit. Under the agent's
// CPUQuota=2% a fork costs ~0.4s, and eight separate calls measured 3.1s on a
// real controller — the two dozen here were most of a 20s probe budget, and the
// probe timed out before it could answer.
func TestOpenStackAsksSystemdOnce(t *testing.T) {
	h := &fakeHost{systemd: map[string]string{"nova-compute": "active"}}
	h.probe().Collect(context.Background())

	var calls int
	for _, c := range h.calls {
		if strings.HasPrefix(c, "systemctl ") {
			calls++
		}
	}
	if calls != 1 {
		t.Errorf("%d systemctl calls for %d services, want 1", calls, len(osServices))
	}
}

// Pairing values up when the output shape is not what the parser assumes would
// attribute one unit's state to another. A silently wrong answer is worse than
// no answer, so a mismatch yields nothing rather than a guess.
func TestOpenStackDiscardsMisshapenSystemdOutput(t *testing.T) {
	p := &OpenStack{root: "/nonexistent", run: func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "systemctl" {
			return []byte("loaded\nactive\n"), nil // one unit's worth, many asked
		}
		return nil, exec.ErrNotFound
	}}
	res := p.Collect(context.Background())

	if len(res.Roles) != 0 {
		t.Errorf("roles = %v — misaligned output was read as an answer", res.Roles)
	}
}

// A containerised service reports the tag it was deployed with. Reading it out
// of the listing is free; asking the container would mean `podman exec`, the
// fork that aborts inside this agent's cgroup.
func TestOpenStackTakesTheVersionFromTheDeployedImageTag(t *testing.T) {
	h := &fakeHost{}
	p := h.probeWithSocket(t, "/run/podman/podman.sock", func() (map[string]containerInfo, error) {
		return map[string]containerInfo{
			"nova_compute": {State: "running", Image: "172.16.0.11:7777/openstack.kolla/nova-compute:2025.1-rocky-9"},
			"keystone":     {State: "running", Image: "172.16.0.11:7777/openstack.kolla/keystone:2025.1-rocky-9"},
		}, nil
	})
	res := p.Collect(context.Background())

	if got := res.Components["nova-compute"].Version; got != "2025.1" {
		t.Errorf("nova-compute version = %q, want the deployed release 2025.1", got)
	}
	if got := res.Components["keystone"].Version; got != "2025.1" {
		t.Errorf("keystone version = %q", got)
	}
}

// The registry in this fleet carries a port, so "everything after the last
// colon" would read 7777/... as the tag of an untagged image.
func TestImageTagIsNotConfusedByARegistryPort(t *testing.T) {
	for ref, want := range map[string]string{
		"172.16.0.11:7777/openstack.kolla/nova-compute:2025.1-rocky-9": "2025.1-rocky-9",
		"172.16.0.11:7777/openstack.kolla/nova-compute":                "",
		"nova-compute:2025.1": "2025.1",
		"nova-compute":        "",
	} {
		if got := imageTag(ref); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", ref, got, want)
		}
	}
}

// A tag that is not a release number still identifies what is deployed.
// gpu02 runs nova-compute:260618, a custom build, where every other compute
// node in the fleet runs 2025.1-rocky-9 — and discarding the tag hid the most
// interesting fact about that host behind an empty cell.
func TestOpenStackKeepsANonReleaseImageTag(t *testing.T) {
	h := &fakeHost{}
	p := h.probeWithSocket(t, "/run/podman/podman.sock", func() (map[string]containerInfo, error) {
		return map[string]containerInfo{
			"nova_compute": {State: "running", Image: "172.16.0.11:7777/openstack.kolla/nova-compute:260618"},
			"keystone":     {State: "running", Image: "172.16.0.11:7777/openstack.kolla/keystone:2025.1-rocky-9"},
		}, nil
	})
	res := p.Collect(context.Background())

	if got := res.Components["nova-compute"].Version; got != "260618" {
		t.Errorf("nova-compute version = %q, want the deployed tag 260618", got)
	}
	// The release tag still reduces to the release, so the common case is not
	// turned into noise.
	if got := res.Components["keystone"].Version; got != "2025.1" {
		t.Errorf("keystone version = %q, want 2025.1", got)
	}
}

// docker cannot work without its socket, so the socket's absence is the answer
// — there are no containers — not a failure to look.
//
// One host has docker installed with the unit masked, which is somebody saying
// on purpose that it does not run there. Calling the CLI anyway returned
// "Cannot connect to the Docker daemon" and parked the host permanently in the
// "could not be probed" column.
func TestOpenStackTreatsAStoppedDockerDaemonAsNoContainers(t *testing.T) {
	h := &fakeHost{
		engineAbsent: map[string]bool{"podman": true},
		systemd:      map[string]string{"nova-compute": "active"},
	}
	// docker is installed and would fail: no socket exists under the test root.
	res := h.probe().Collect(context.Background())

	if res.Err != nil {
		t.Fatalf("a masked docker was reported as a probe failure: %v", res.Err)
	}
	for _, c := range h.calls {
		if strings.HasPrefix(c, "docker ") {
			t.Errorf("the docker CLI was run (%q) with no socket for it to reach", c)
		}
	}
	if !slices.Contains(res.Roles, "compute") {
		t.Errorf("roles = %v — the systemd answer was lost", res.Roles)
	}
}

// Inside the agent's unit the container engine CLI is not an option: it is a
// large Go program inheriting MemoryMax=48M and TasksMax=24, and on a real
// controller both engines aborted with a core dump.
//
// The two ways of reaching that branch are different answers, and collapsing
// them is how this goes wrong in either direction. Most of the fleet has no
// engine at all, and calling that a failure moves a dozen healthy hosts into
// "could not be probed" every hour. An engine installed with its socket not
// exposed is the other case, and calling *that* an absence is what once filed a
// full Kolla controller as running no OpenStack.
func TestConfinedProbeNeitherForksNorInventsAnAbsence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed []string
		wantErr   bool
	}{
		{
			// The common shape: no socket, no engine, nothing to look at.
			name: "a host with no container engine is an absence",
		},
		{
			// Somebody installed podman and did not enable podman.socket.
			name:      "an engine with no socket is a failure to look",
			installed: []string{"podman"},
			wantErr:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &fakeHost{}
			p := &OpenStack{
				root: "/nonexistent", run: h.run, confined: true,
				lookPath: func(name string) (string, error) {
					if slices.Contains(tc.installed, name) {
						return "/usr/bin/" + name, nil
					}
					return "", exec.ErrNotFound
				},
			}

			_, err := p.containerIndex(context.Background())
			if tc.wantErr && err == nil {
				t.Error("an installed engine with no socket was reported as no containers")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("a host with no container engine reported a failure: %v", err)
			}
			for _, c := range h.calls {
				if strings.HasPrefix(c, "podman ") || strings.HasPrefix(c, "docker ") {
					t.Errorf("the engine CLI was forked (%q) inside the unit that cannot run it", c)
				}
			}
		})
	}
}

// The fallback still exists for the case it was written for: a probe run by
// hand, outside the unit, where the CLI works fine. Gating on the cgroup must
// not quietly delete that path.
func TestAnUnconfinedProbeStillUsesTheCLI(t *testing.T) {
	h := &fakeHost{containers: map[string]string{"nova_compute": "running"}}
	p := &OpenStack{root: "/nonexistent", run: h.run}

	index, err := p.containerIndex(context.Background())
	if err != nil {
		t.Fatalf("containerIndex: %v", err)
	}
	if _, ok := index["nova_compute"]; !ok {
		t.Errorf("index = %v, want the container the CLI reported", index)
	}
}

// A container engine that will not answer costs the containers, not the pass.
//
// Refusing outright threw away evidence this probe had not looked for yet:
// services deployed as systemd units are visible without asking any engine, and
// a host that has them is not a host we failed to read. Reporting it as
// unprobed says "we could not tell" about a machine we could — and that is the
// column an operator scans for hosts needing attention.
func TestAContainerFailureDoesNotDiscardSystemdEvidence(t *testing.T) {
	h := &fakeHost{systemd: map[string]string{
		"nova-compute":              "active",
		"neutron-openvswitch-agent": "active",
	}}
	p := h.probeWithSocket(t, "/run/podman/podman.sock", func() (map[string]containerInfo, error) {
		return nil, errors.New("connection refused")
	})
	res := p.Collect(context.Background())

	if res.Err != nil {
		t.Fatalf("a host whose services systemd can see was reported unprobed: %v", res.Err)
	}
	if !slices.Contains(res.Roles, "compute") {
		t.Errorf("roles = %v, want what systemd could see", res.Roles)
	}
	// The engine's silence still has to be visible — it cost detail, and
	// somebody has to be able to find out why.
	if res.Details["container_probe_error"] == "" {
		t.Error("the container failure vanished; nothing says why the answer is thinner")
	}
}

// And the refusal stands exactly where it was written to stand.
//
// A Kolla host runs its services as containers, so systemd sees nothing there.
// Nothing found plus no way to ask the engine is "we could not tell", and
// calling it absent is what once filed a full controller as running no
// OpenStack.
func TestAContainerFailureWithNothingElseFoundStillRefuses(t *testing.T) {
	h := &fakeHost{}
	p := h.probeWithSocket(t, "/run/podman/podman.sock", func() (map[string]containerInfo, error) {
		return nil, errors.New("connection refused")
	})
	res := p.Collect(context.Background())

	if res.Err == nil {
		t.Fatal("a host we could not read was reported as running no OpenStack")
	}
	if res.Detected {
		t.Error("detected is set on a probe that could not tell")
	}
}
