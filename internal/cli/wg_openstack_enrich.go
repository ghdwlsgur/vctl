package cli

import (
	"maps"
	"slices"

	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// enrichWGAnnotations joins the two inventories the WireGuard views already read:
// a WireGuard endpoint's underlay address and OpenStack's VM address identify
// the same VM, while Nova's hypervisor name identifies its physical compute
// host. The result is ephemeral page data; operator annotations remain the
// authority and are never written back or overwritten.
func enrichWGAnnotations(
	ifaces []store.WGInterfaceRow,
	servers []store.Server,
	manual []store.WGEndpointAnnotation,
	instances []store.Instance,
	osHosts []store.OpenStackHost,
) []store.WGEndpointAnnotation {
	endpointsByIP := wgEndpointsByUnderlayIP(ifaces, servers, manual)
	parentByNova := novaParentByFarmHost(instances, osHosts)
	candidates := wgVMCandidates(instances, endpointsByIP)

	out := append([]store.WGEndpointAnnotation(nil), manual...)
	index := make(map[string]int, len(out))
	for i, a := range out {
		index[a.PublicKey] = i
	}
	for _, key := range slices.Sorted(maps.Keys(candidates)) {
		cs := candidates[key]
		// One key that resolves to two different VMs identifies neither.
		if wgCandidatesDisagree(cs) {
			continue
		}
		a := store.WGEndpointAnnotation{PublicKey: key}
		if i, ok := index[key]; ok {
			a = out[i]
		}
		a = fillWGAnnotation(a, cs, parentByNova)
		if i, ok := index[key]; ok {
			out[i] = a
			continue
		}
		index[key] = len(out)
		out = append(out, a)
	}
	return out
}

// wgEndpoint is one public key reachable at an underlay address, and whether
// that pairing came from a collected interface or an operator annotation.
type wgEndpoint struct {
	key, inventoryHost string
	collected          bool
}

// wgCandidate is a VM that could be the far end of one public key.
type wgCandidate struct {
	instance      store.Instance
	underlayIP    string
	inventoryHost string
	collected     bool
}

// wgEndpointsByUnderlayIP answers "which public keys answer on this address",
// from both collected interfaces (via their host's inventory addresses) and
// operator annotations.
func wgEndpointsByUnderlayIP(ifaces []store.WGInterfaceRow, servers []store.Server,
	manual []store.WGEndpointAnnotation) map[string][]wgEndpoint {
	serversByHost := make(map[string]store.Server, len(servers))
	for _, s := range servers {
		serversByHost[s.Hostname] = s
	}

	byIP := map[string][]wgEndpoint{}
	for _, i := range ifaces {
		s, ok := serversByHost[i.Host]
		if !ok || i.PublicKey == "" {
			continue
		}
		for _, ip := range append([]string{s.IP}, s.ExtraIPs...) {
			if ip != "" {
				byIP[ip] = append(byIP[ip], wgEndpoint{key: i.PublicKey, inventoryHost: i.Host, collected: true})
			}
		}
	}
	for _, a := range manual {
		if a.PublicKey != "" && a.UnderlayIP != "" {
			byIP[a.UnderlayIP] = append(byIP[a.UnderlayIP], wgEndpoint{key: a.PublicKey, inventoryHost: a.InventoryHost})
		}
	}
	return byIP
}

// novaParentByFarmHost answers "which inventory host is the compute node Nova
// calls <name>", keyed by farm and Nova hostname.
//
// Resolution stays within a farm. Doing it fleet-wide would make gpu05
// ambiguous as soon as another deployment used the same conventional hostname.
func novaParentByFarmHost(instances []store.Instance, osHosts []store.OpenStackHost) map[string]string {
	localsByFarm := map[string][]string{}
	for _, h := range osHosts {
		if h.Farm != "" {
			localsByFarm[h.Farm] = append(localsByFarm[h.Farm], h.Hostname)
		}
	}
	controlsByFarm := map[string][]string{}
	seenControl := map[string]bool{}
	for _, vm := range instances {
		k := vm.DeploymentID + "\x00" + vm.HypervisorHostname
		if vm.DeploymentID != "" && vm.HypervisorHostname != "" && !seenControl[k] {
			seenControl[k] = true
			controlsByFarm[vm.DeploymentID] = append(controlsByFarm[vm.DeploymentID], vm.HypervisorHostname)
		}
	}
	parentByNova := map[string]string{}
	for farm, controls := range controlsByFarm {
		pairs, _ := membership.MatchHosts(localsByFarm[farm], controls)
		for inventoryHost, novaHost := range pairs {
			parentByNova[farm+"\x00"+novaHost] = inventoryHost
		}
	}
	return parentByNova
}

// wgVMCandidates answers "which VMs could be behind each public key", by
// matching a VM address against the addresses endpoints answer on. Instances
// the control plane no longer reports are skipped.
func wgVMCandidates(instances []store.Instance, endpointsByIP map[string][]wgEndpoint) map[string][]wgCandidate {
	candidates := map[string][]wgCandidate{}
	for _, vm := range instances {
		if vm.MissingSince != nil {
			continue
		}
		for _, addr := range vm.Addresses {
			for _, ep := range endpointsByIP[addr.Address] {
				candidates[ep.key] = append(candidates[ep.key], wgCandidate{
					instance: vm, underlayIP: addr.Address, inventoryHost: ep.inventoryHost, collected: ep.collected,
				})
			}
		}
	}
	return candidates
}

// wgCandidatesDisagree reports candidates that name more than one VM.
func wgCandidatesDisagree(cs []wgCandidate) bool {
	first := cs[0]
	for _, c := range cs[1:] {
		if c.instance.DeploymentID != first.instance.DeploymentID || c.instance.InstanceID != first.instance.InstanceID {
			return true
		}
	}
	return false
}

// fillWGAnnotation fills only the blanks. Operator annotations are the
// authority, so a field they already set is left exactly as it is.
func fillWGAnnotation(a store.WGEndpointAnnotation, cs []wgCandidate,
	parentByNova map[string]string) store.WGEndpointAnnotation {
	first := cs[0]
	if a.Label == "" {
		a.Label = first.instance.Name
	}
	collected := false
	for _, c := range cs {
		collected = collected || c.collected
	}
	// A key we collected an interface for is a gateway in its own right; only
	// an uncollected one is inferred to be a plain VM.
	if a.Kind == "" && !collected {
		a.Kind = "vm"
	}
	if a.UnderlayIP == "" {
		a.UnderlayIP = first.underlayIP
	}
	if a.InventoryHost == "" {
		a.InventoryHost = first.inventoryHost
	}
	if a.ParentHostname == "" {
		a.ParentHostname = parentByNova[first.instance.DeploymentID+"\x00"+first.instance.HypervisorHostname]
	}
	return a
}
