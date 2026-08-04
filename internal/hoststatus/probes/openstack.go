// Package probes holds the per-platform capability probes the node agent runs
// alongside its heartbeat.
package probes

import (
	"context"
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
}

// NewOpenStack returns a probe that reads the live host.
func NewOpenStack() *OpenStack { return &OpenStack{} }

func (p *OpenStack) Kind() string { return "openstack" }

// osService maps a unit/container name to the role it implies.
//
// Presence of the service is the evidence, not presence of a package. A host
// with python3-openstackclient installed is an operator's workstation, not a
// compute node, and treating the two the same is how an inventory ends up
// claiming machines that run nothing.
var osServices = []struct {
	name string
	role string
}{
	{"nova-compute", "compute"},
	{"nova-conductor", "controller"},
	{"nova-scheduler", "controller"},
	{"nova-api", "controller"},
	{"neutron-l3-agent", "network"},
	{"neutron-dhcp-agent", "network"},
	{"neutron-openvswitch-agent", "network"},
	{"cinder-volume", "block-storage"},
	{"glance-api", "image"},
	{"keystone", "identity"},
	{"placement-api", "controller"},
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

	roles := map[string]bool{}
	for _, s := range osServices {
		active, found := p.serviceState(ctx, s.name)
		if !found {
			continue
		}
		res.Components[s.name] = hoststatus.Component{Active: active, Service: true}
		// Only a running service claims the role. An installed-but-stopped unit
		// says the host was meant to do this, which is worth reporting as a
		// component, but it is not doing it now.
		if active {
			roles[s.role] = true
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

	if v := p.novaVersion(ctx); v != "" {
		c := res.Components["nova-compute"]
		c.Version = v
		res.Components["nova-compute"] = c
	}

	res.Roles = sortedKeys(roles)
	// Detected means "this host is part of a deployment", which requires a
	// service, not a package. Components with no active service still count —
	// a stopped nova-compute is a compute node that is down, not a host with no
	// OpenStack on it.
	res.Detected = len(res.Components) > 0

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

// serviceState reports whether a service exists on this host and whether it is
// running, covering both systemd units and Kolla's containers.
//
// Kolla is the reason this is not just `systemctl is-active`: in that
// deployment every OpenStack service is a container and the host has no unit
// for it at all, so a systemd-only probe would report a full controller as
// empty.
func (p *OpenStack) serviceState(ctx context.Context, name string) (active, found bool) {
	// LoadState, not is-active.
	//
	// `systemctl is-active` prints "inactive" for a unit that does not exist,
	// so it cannot tell "installed and stopped" from "never installed" — every
	// service in the table came back as present, and an operator's workstation
	// read as a full controller. LoadState says not-found for the second case,
	// which is the distinction this whole probe rests on.
	if out, err := p.exec(ctx, "systemctl", "show", "-p", "LoadState", "-p", "ActiveState", "--value", name+".service"); err == nil {
		load, act := parseShow(string(out))
		if load != "" && load != "not-found" {
			return act == "active", true
		}
	}
	for _, engine := range []string{"podman", "docker"} {
		out, err := p.exec(ctx, engine, "ps", "-a", "--filter", "name=^"+name+"$", "--format", "{{.Names}} {{.State}}")
		if err != nil || len(strings.TrimSpace(string(out))) == 0 {
			continue
		}
		line := strings.Fields(strings.TrimSpace(string(out)))
		if len(line) >= 2 {
			return line[1] == "running", true
		}
		return false, true
	}
	return false, false
}

// novaVersion asks nova-compute what it is. The binary is authoritative about
// itself in a way a package name is not — a container image or a source install
// has no package to read.
func (p *OpenStack) novaVersion(ctx context.Context) string {
	if v := p.commandVersion(ctx, "nova-compute", "--version"); v != "" {
		return v
	}
	for _, engine := range []string{"podman", "docker"} {
		out, err := p.exec(ctx, engine, "exec", "nova_compute", "nova-compute", "--version")
		if err == nil {
			if m := versionRe.FindSubmatch(out); m != nil {
				return string(m[1])
			}
		}
	}
	return ""
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

// parseShow reads `systemctl show --value` output: one value per line, in the
// order the -p flags were given.
func parseShow(out string) (loadState, activeState string) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > 0 {
		loadState = strings.TrimSpace(lines[0])
	}
	if len(lines) > 1 {
		activeState = strings.TrimSpace(lines[1])
	}
	return loadState, activeState
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
