// Package probes holds the per-platform capability probes the node agent runs
// alongside its heartbeat.
package probes

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/hoststatus"
)

// OpenStack detects an OpenStack deployment on the local host and reports the
// roles it plays and the versions it runs.
//
// # What it does not do
//
// It does not decide which deployment the host belongs to. Local evidence
// cannot answer that: two unrelated farms behind one proxy share a Keystone
// URL, and several farms run the same release. Guessing from it would produce
// the same failure the WireGuard graph had, where a label match was rendered as
// a recorded fact. Membership is left to a reconciler that also sees the
// control plane.
//
// # Why per-component versions
//
// A rolling upgrade leaves nova-compute, libvirt and qemu at different
// versions, sometimes for weeks. "OpenStack 2025.1" on the host would be a
// single number that is wrong for at least one component and cannot say which.
// The components are reported separately and the release is left to whoever can
// see the whole deployment.
type OpenStack struct {
	// root is the filesystem prefix, for tests. Empty means "/".
	root string
	// run executes a command; swapped in tests. Nil means real execution.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
	// listSocket asks a container engine's socket for its containers; swapped
	// in tests. Nil means the real HTTP-over-unix-socket client.
	listSocket func(ctx context.Context, socket string) (map[string]containerInfo, error)
}

// NewOpenStack returns a probe that reads the live host.
func NewOpenStack() *OpenStack { return &OpenStack{} }

func (p *OpenStack) Kind() string { return "openstack" }

// osService maps a service to the role it implies.
//
// Presence of the service is the evidence, not presence of a package. A host
// with python3-openstackclient installed is an operator's workstation, not a
// compute node, and treating the two the same is how an inventory ends up
// claiming machines that run nothing.
//
// Names are written the systemd way, with hyphens. Kolla runs the same services
// as containers named with underscores — nova-compute is nova_compute there —
// and serviceState looks for both.
//
// An empty role means "report this component, claim nothing". ovn-controller
// runs on every hypervisor in an OVN deployment, so treating it as a network
// node would label the entire compute fleet as networking.
var osServices = []struct {
	name string
	role string
}{
	{"nova-compute", "compute"},
	{"nova-conductor", "controller"},
	{"nova-scheduler", "controller"},
	{"nova-api", "controller"},
	{"placement-api", "controller"},

	// Classic ML2/agent networking.
	{"neutron-l3-agent", "network"},
	{"neutron-dhcp-agent", "network"},
	{"neutron-openvswitch-agent", "network"},
	// OVN networking. Without these an OVN deployment — which is what Kolla
	// installs by default now — reports no network node anywhere, because none
	// of the agent names above exist in it.
	{"neutron-server", "network"},
	{"ovn-northd", "network"},
	{"ovn-nb-db", "network"},
	{"ovn-sb-db", "network"},

	{"cinder-volume", "block-storage"},
	{"cinder-api", "block-storage"},
	{"cinder-scheduler", "block-storage"},
	{"cinder-backup", "block-storage"},
	{"glance-api", "image"},
	{"keystone", "identity"},
	{"heat-engine", "orchestration"},
	{"heat-api", "orchestration"},
	{"octavia-worker", "load-balancer"},
	{"octavia-api", "load-balancer"},
	{"horizon", "dashboard"},

	// Present on every node of their kind, so they describe the host without
	// naming a role of their own.
	{"ovn-controller", ""},
	{"neutron-ovn-metadata-agent", ""},
	{"nova-libvirt", ""},
}

// versionRe pulls the first dotted version out of a command's output. Version
// banners differ per component and per packaging; the number is the part they
// agree on.
var versionRe = regexp.MustCompile(`\b(\d+\.\d+(?:\.\d+)?)\b`)

func (p *OpenStack) Collect(ctx context.Context) hoststatus.ProbeResult {
	res := hoststatus.ProbeResult{
		Kind:       p.Kind(),
		Components: map[string]hoststatus.Component{},
		Details:    map[string]string{},
		ObservedAt: time.Now(),
	}

	// One listing per engine for the whole pass, not one per service. Asking
	// podman about each of two dozen services separately was ~50 forks a pass on
	// a host whose agent runs under CPUQuota=2%.
	containers, err := p.containerIndex(ctx)
	if err != nil {
		// An engine is installed and would not answer. That is not the same as a
		// host with no containers on it, and the difference is the whole probe:
		// reporting "none found" here told us a full Kolla controller runs no
		// OpenStack. Refuse to answer instead.
		res.Err = err
		return res
	}

	units := make([]string, 0, len(osServices))
	for _, s := range osServices {
		units = append(units, s.name+".service")
	}
	systemd := p.systemdIndex(ctx, units)

	roles := map[string]bool{}
	active := map[string]bool{}
	for _, s := range osServices {
		isActive, found, image := serviceState(systemd, containers, s.name)
		if !found {
			continue
		}
		comp := hoststatus.Component{Active: isActive, Service: true}
		// For a containerised service the deployed image tag is the version:
		// it is what was actually rolled out, and it is already in the listing.
		// Asking the container itself would mean `podman exec`, which is the
		// fork this probe cannot afford — it aborts inside the agent's cgroup.
		if v := versionFromImage(image); v != "" {
			comp.Version = v
		}
		res.Components[s.name] = comp
		if s.role == "" {
			continue
		}
		// Deployed claims the role; running claims it as active. A stopped
		// nova-compute means a compute node that is down, not a host that
		// stopped being one — and the farm view has to keep showing it or the
		// topology shrinks whenever something breaks.
		roles[s.role] = true
		if isActive {
			active[s.role] = true
		}
	}

	// Hypervisor facts matter for a compute node and are meaningless elsewhere,
	// so they are only gathered when one was found.
	if roles["compute"] {
		if v := p.commandVersion(ctx, "libvirtd", "--version"); v != "" {
			// libvirtd is a daemon, and it was reached by asking the daemon's own
			// binary for its version — which only answers when it is installed.
			res.Components["libvirt"] = hoststatus.Component{Version: v, Active: true, Service: true}
		}
		if v := p.commandVersion(ctx, "qemu-system-x86_64", "--version"); v != "" {
			// Not a service: qemu is exec'd per instance. Marking it as one made
			// every healthy compute node carry a stopped component.
			res.Components["qemu"] = hoststatus.Component{Version: v}
		}
		if p.exists("/dev/kvm") {
			res.Details["hypervisor"] = "kvm"
		}
	}

	if c, ok := res.Components["nova-compute"]; ok && c.Version == "" {
		if v := p.novaVersion(ctx); v != "" {
			c.Version = v
			res.Components["nova-compute"] = c
		}
	}

	res.Roles = sortedKeys(roles)
	res.ActiveRoles = sortedKeys(active)
	// Detected means "this host is part of a deployment", which requires a
	// service, not a package. Components with no active service still count —
	// a stopped nova-compute is a compute node that is down, not a host with no
	// OpenStack on it.
	res.Detected = len(res.Components) > 0

	// Which Keystone this host authenticates against. It is evidence of
	// membership, not proof: two deployments behind one proxy share an endpoint.
	// The reader decides what to do with it and labels the result local-only.
	if v := p.keystoneURL(); v != "" {
		res.Details["keystone_url"] = v
	}

	// Whether new VMs on this farm will trust the vctl SSH CA. Filed per host
	// because only the host can see it; folded per farm by the reader, since a
	// farm is only as onboarded as the service that answers 169.254.169.254.
	if st, svc := p.vendordataState(); st != "" {
		res.Details["vendordata"] = st
		res.Details["vendordata_service"] = svc
	}

	// Deliberately not decided here. Local evidence cannot separate two farms
	// that share an endpoint, and a wrong answer would be rendered as fact.
	res.Details["deployment"] = "unknown"
	if id := p.deploymentID(); id != "" {
		// The one exception: an identifier somebody placed on the host on
		// purpose. That is a statement, not an inference.
		res.Details["deployment"] = id
		res.Details["deployment_source"] = "declared"
	}
	return res
}

// deploymentIDPath is where a deployment stamps its immutable identifier, if it
// does. Written by whatever installs the fleet (Kolla, Ansible), never derived.
const deploymentIDPath = "/etc/openstack/deployment-id"

func (p *OpenStack) deploymentID() string {
	b, err := os.ReadFile(p.path(deploymentIDPath))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// containerEngines is the CLI fallback, for hosts with no engine socket.
//
// The socket is the primary path (see containers.go): a container engine CLI is
// a large Go program, and this agent's unit is sized for a heartbeat, so
// running one inside the cgroup aborts it. This stays for hosts where no socket
// is exposed but a CLI would work — an agent run outside systemd, for instance.
var containerEngines = []struct {
	name string
	args []string
	// daemonSocket, when set, is the socket this engine cannot work without.
	// Its absence means the daemon is not running, and therefore that there are
	// no containers — an answer, not a failure to look.
	//
	// One host in this fleet has docker installed and the unit masked, which is
	// somebody saying on purpose that it does not run there. Calling the CLI
	// anyway produced "Cannot connect to the Docker daemon" and left the host
	// permanently in the "could not be probed" column.
	daemonSocket string
}{
	// podman is daemonless: its CLI reads the local store, so there is nothing
	// equivalent to check.
	{"podman", []string{"ps", "-a", "--format", "{{.Names}} {{.State}}"}, ""},
	{"docker", []string{"ps", "-a", "--format", "{{.Names}} {{.State}}"}, "/var/run/docker.sock"},
}

// containerIndex lists every container on the host once, so the per-service
// lookup is a map read rather than a fork.
//
// An engine that is not installed is not an error — most of the fleet has
// none. An engine that is installed and will not answer is, and it must not be
// allowed to look like a host with nothing on it: that is exactly what reported
// a full Kolla controller as running no OpenStack.
func (p *OpenStack) containerIndex(ctx context.Context) (map[string]containerInfo, error) {
	index := map[string]containerInfo{}
	var failures []string
	var asked bool
	for _, s := range containerSockets {
		if !p.exists(s.path) {
			continue
		}
		asked = true
		found, err := p.socketList(ctx, s.path)
		if err != nil {
			failures = append(failures, s.engine+" socket: "+err.Error())
			continue
		}
		mergeContainers(index, found)
	}
	// Only when no socket exists at all. A host that exposes one and refuses is
	// a failure to report, not a reason to fork the CLI that cannot run here.
	if !asked {
		for _, engine := range containerEngines {
			if engine.daemonSocket != "" && !p.exists(engine.daemonSocket) {
				continue
			}
			out, err := p.exec(ctx, engine.name, engine.args...)
			if err != nil {
				if !notInstalled(err) {
					failures = append(failures, engine.name+": "+err.Error())
				}
				continue
			}
			addContainers(index, string(out))
		}
	}
	if len(failures) > 0 {
		return nil, fmt.Errorf("could not list containers (%s)", strings.Join(failures, "; "))
	}
	return index, nil
}

func (p *OpenStack) socketList(ctx context.Context, socket string) (map[string]containerInfo, error) {
	if p.listSocket != nil {
		return p.listSocket(ctx, socket)
	}
	return listViaSocket(ctx, socket)
}

// mergeContainers keeps the first engine's answer for a name, so a host running
// both does not report one service twice with different states.
func mergeContainers(index, found map[string]containerInfo) {
	for name, state := range found {
		if _, seen := index[name]; !seen {
			index[name] = state
		}
	}
}

// notInstalled reports whether the command was simply absent, which is the one
// failure that means "this host does not use that engine" rather than "the
// probe could not look".
func notInstalled(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist)
}

func addContainers(index map[string]containerInfo, out string) {
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		// First engine wins: a host running both should not have the same
		// service reported twice with different states.
		if _, seen := index[f[0]]; !seen {
			index[f[0]] = containerInfo{State: f[1]}
		}
	}
}

// versionFromImage reads the release out of a deployed image tag.
//
// Kolla tags are like 2025.1-rocky-9, so this reports the OpenStack release
// rather than the component's own package version. That is the honest answer
// for a containerised service: the tag is what was deployed for it.
func versionFromImage(image string) string {
	tag := imageTag(image)
	if tag == "" {
		return ""
	}
	if m := versionRe.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	// A tag with no version in it is returned whole rather than discarded. One
	// compute node in this fleet runs nova-compute:260618 — a custom build,
	// where every other node runs 2025.1-rocky-9 — and reporting nothing for it
	// hid the single most interesting fact about that host behind an empty
	// cell. The tag identifies what is deployed even when it is not a release.
	return tag
}

// systemdIndex asks about every unit in one call.
//
// LoadState, not is-active. `systemctl is-active` prints "inactive" for a unit
// that does not exist, so it cannot tell "installed and stopped" from "never
// installed" — every service in the table came back as present, and an
// operator's workstation read as a full controller. LoadState says not-found
// for the second case, which is the distinction this whole probe rests on.
//
// One call rather than one per unit, because the agent runs under CPUQuota=2%
// where a fork costs ~0.4s. Measured on a real controller: eight separate
// `systemctl show` calls took 3.1s, so the two dozen here were ~9s of a 20s
// probe budget, and the probe timed out before it could answer.
//
// `systemctl show -p A -p B --value u1 u2 u3` prints two value lines per unit,
// in the order given, separated by a blank line.
func (p *OpenStack) systemdIndex(ctx context.Context, units []string) map[string][2]string {
	args := append([]string{"show", "-p", "LoadState", "-p", "ActiveState", "--value"}, units...)
	out, err := p.exec(ctx, "systemctl", args...)
	if err != nil {
		return nil
	}
	var values []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			values = append(values, line)
		}
	}
	// A mismatch means the output shape is not what this parser assumes, and
	// pairing up anyway would attribute one unit's state to another — a silently
	// wrong answer, which is worse than no answer.
	if len(values) != 2*len(units) {
		return nil
	}
	index := make(map[string][2]string, len(units))
	for i, u := range units {
		index[u] = [2]string{values[2*i], values[2*i+1]}
	}
	return index
}

// serviceState reports whether a service exists on this host and whether it is
// running, covering both systemd units and Kolla's containers.
//
// Kolla is the reason this is not just systemd: in that deployment every
// OpenStack service is a container and the host has no unit for it at all, so a
// systemd-only probe would report a full controller as empty.
func serviceState(units map[string][2]string, containers map[string]containerInfo, name string) (active, found bool, image string) {
	if v, ok := units[name+".service"]; ok && v[0] != "" && v[0] != "not-found" {
		return v[1] == "active", true, ""
	}
	for _, cname := range containerNames(name) {
		if c, ok := containers[cname]; ok {
			return c.State == "running", true, c.Image
		}
	}
	return false, false, ""
}

// containerNames is what this service could be called as a container.
//
// Kolla names containers with underscores — nova-compute the unit is
// nova_compute the container. Filtering on the hyphenated name found nothing on
// a full controller, and the host reported as having no OpenStack on it at all.
// The test that was supposed to cover this used hyphenated names in its fake,
// so it agreed with the bug instead of catching it.
func containerNames(service string) []string {
	if under := strings.ReplaceAll(service, "-", "_"); under != service {
		return []string{under, service}
	}
	return []string{service}
}

// novaVersion asks the nova-compute binary what it is. The binary is
// authoritative about itself in a way a package name is not.
//
// There is no container fallback. It used to run `podman exec nova_compute`,
// which aborts inside this agent's cgroup and would leave a core dump on every
// Kolla host every hour. Containerised nova gets its version from the image tag
// instead, which the listing already carries.
func (p *OpenStack) novaVersion(ctx context.Context) string {
	return p.commandVersion(ctx, "nova-compute", "--version")
}

func (p *OpenStack) commandVersion(ctx context.Context, name string, args ...string) string {
	out, err := p.exec(ctx, name, args...)
	if err != nil && len(out) == 0 {
		return ""
	}
	if m := versionRe.FindSubmatch(out); m != nil {
		return string(m[1])
	}
	return ""
}

func (p *OpenStack) exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	if p.run != nil {
		return p.run(ctx, name, args...)
	}
	// CombinedOutput: several of these write their version banner to stderr.
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func (p *OpenStack) exists(path string) bool {
	_, err := os.Stat(p.path(path))
	return err == nil
}

func (p *OpenStack) path(abs string) string {
	if p.root == "" {
		return abs
	}
	return p.root + abs
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
