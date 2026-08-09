package cli

import (
	"sort"

	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// enrichWGAnnotations joins the two inventories the dashboard already reads:
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
	type endpoint struct {
		key, inventoryHost string
		collected          bool
	}
	type candidate struct {
		instance      store.Instance
		underlayIP    string
		inventoryHost string
		collected     bool
	}

	serversByHost := make(map[string]store.Server, len(servers))
	for _, s := range servers {
		serversByHost[s.Hostname] = s
	}

	endpointsByIP := map[string][]endpoint{}
	for _, i := range ifaces {
		s, ok := serversByHost[i.Host]
		if !ok || i.PublicKey == "" {
			continue
		}
		ips := append([]string{s.IP}, s.ExtraIPs...)
		for _, ip := range ips {
			if ip != "" {
				endpointsByIP[ip] = append(endpointsByIP[ip], endpoint{key: i.PublicKey, inventoryHost: i.Host, collected: true})
			}
		}
	}
	for _, a := range manual {
		if a.PublicKey != "" && a.UnderlayIP != "" {
			endpointsByIP[a.UnderlayIP] = append(endpointsByIP[a.UnderlayIP], endpoint{key: a.PublicKey, inventoryHost: a.InventoryHost})
		}
	}

	// Resolve Nova's short hypervisor names within their own farm. Doing this
	// fleet-wide would make gpu05 ambiguous as soon as another deployment used
	// the same conventional hostname.
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

	candidates := map[string][]candidate{}
	for _, vm := range instances {
		if vm.MissingSince != nil {
			continue
		}
		for _, addr := range vm.Addresses {
			for _, ep := range endpointsByIP[addr.Address] {
				candidates[ep.key] = append(candidates[ep.key], candidate{
					instance: vm, underlayIP: addr.Address, inventoryHost: ep.inventoryHost, collected: ep.collected,
				})
			}
		}
	}

	out := append([]store.WGEndpointAnnotation(nil), manual...)
	index := make(map[string]int, len(out))
	for i, a := range out {
		index[a.PublicKey] = i
	}
	keys := make([]string, 0, len(candidates))
	for key := range candidates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		cs := candidates[key]
		first := cs[0]
		ambiguous := false
		for _, c := range cs[1:] {
			if c.instance.DeploymentID != first.instance.DeploymentID || c.instance.InstanceID != first.instance.InstanceID {
				ambiguous = true
				break
			}
		}
		if ambiguous {
			continue
		}

		a := store.WGEndpointAnnotation{PublicKey: key}
		if i, ok := index[key]; ok {
			a = out[i]
		}
		if a.Label == "" {
			a.Label = first.instance.Name
		}
		collected := false
		for _, c := range cs {
			collected = collected || c.collected
		}
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
		if i, ok := index[key]; ok {
			out[i] = a
		} else {
			index[key] = len(out)
			out = append(out, a)
		}
	}
	return out
}
