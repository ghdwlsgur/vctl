package openstackapi

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Instance is one VM as the control plane knows it.
type Instance struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ProjectID string `json:"project_id,omitempty"`

	Status     string `json:"status,omitempty"`
	PowerState string `json:"power_state,omitempty"`
	TaskState  string `json:"task_state,omitempty"`

	AvailabilityZone   string `json:"availability_zone,omitempty"`
	HypervisorHostname string `json:"hypervisor_hostname,omitempty"`

	FlavorID string `json:"flavor_id,omitempty"`
	ImageID  string `json:"image_id,omitempty"`

	Created time.Time `json:"created,omitempty"`
	Updated time.Time `json:"updated,omitempty"`

	Addresses []InstanceAddress `json:"addresses,omitempty"`
}

// InstanceAddress is one address a VM answers on.
type InstanceAddress struct {
	NetworkName string `json:"network_name"`
	Address     string `json:"address"`
	// fixed | floating
	Type      string `json:"type,omitempty"`
	IPVersion int    `json:"ip_version"`
}

// powerStates maps nova's numeric OS-EXT-STS:power_state onto the names the
// rest of OpenStack uses for it. The number alone is unreadable in a listing
// and means nothing to anyone who has not memorised the table.
var powerStates = map[int]string{
	0: "nostate", 1: "running", 3: "paused", 4: "shutdown", 6: "crashed", 7: "suspended",
}

// instancePageSize bounds one request. A deployment with thousands of VMs must
// not be asked for in one response by a process that also has to stay small.
const instancePageSize = 200

// instanceLimit is the most VMs one collection will take from a deployment.
//
// A ceiling rather than no ceiling: an unbounded loop against an API that keeps
// answering is how a reconciler turns a paging bug into an outage. Well above
// any deployment here, and a caller that hits it is told rather than silently
// truncated.
const instanceLimit = 20000

// Instances lists every VM in the deployment, across all projects.
//
// all_tenants is why this needs an admin credential: without it nova answers
// only for the project the token is scoped to, which for an inventory is
// almost always the wrong answer and — worse — a plausible-looking one.
func (c *Client) Instances(ctx context.Context) ([]Instance, error) {
	var last error
	for _, e := range preferInternal(c.computes) {
		out, err := c.instancesFrom(ctx, e.url)
		if err != nil {
			last = err
			continue
		}
		return out, nil
	}
	return nil, last
}

func (c *Client) instancesFrom(ctx context.Context, base string) ([]Instance, error) {
	var out []Instance
	marker := ""
	for {
		q := url.Values{}
		q.Set("all_tenants", "1")
		q.Set("limit", strconv.Itoa(instancePageSize))
		if marker != "" {
			q.Set("marker", marker)
		}
		var page struct {
			Servers []novaServer `json:"servers"`
		}
		if err := c.getJSON(ctx, base+"/servers/detail?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		for _, s := range page.Servers {
			out = append(out, s.instance())
		}
		if len(page.Servers) < instancePageSize {
			return out, nil
		}
		if len(out) >= instanceLimit {
			return out, fmt.Errorf("stopped at %d instances; the deployment has more", instanceLimit)
		}
		marker = page.Servers[len(page.Servers)-1].ID
	}
}

// novaServer is nova's shape, with the extended attributes an admin token sees.
type novaServer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	TenantID  string `json:"tenant_id"`
	Created   string `json:"created"`
	Updated   string `json:"updated"`
	PowerInt  *int   `json:"OS-EXT-STS:power_state"`
	TaskState string `json:"OS-EXT-STS:task_state"`
	AZ        string `json:"OS-EXT-AZ:availability_zone"`
	Hyper     string `json:"OS-EXT-SRV-ATTR:hypervisor_hostname"`
	Flavor    struct {
		ID string `json:"id"`
	} `json:"flavor"`
	Image any `json:"image"`
	// Addresses is keyed by network name; each entry carries the address, its
	// type and IP version.
	Addresses map[string][]struct {
		Addr    string `json:"addr"`
		Type    string `json:"OS-EXT-IPS:type"`
		Version int    `json:"version"`
	} `json:"addresses"`
}

func (s novaServer) instance() Instance {
	in := Instance{
		ID: s.ID, Name: s.Name, ProjectID: s.TenantID,
		Status: s.Status, TaskState: s.TaskState,
		AvailabilityZone: s.AZ, HypervisorHostname: s.Hyper,
		FlavorID: s.Flavor.ID, ImageID: imageID(s.Image),
		Created: parseNovaTime(s.Created), Updated: parseNovaTime(s.Updated),
	}
	if s.PowerInt != nil {
		if name, ok := powerStates[*s.PowerInt]; ok {
			in.PowerState = name
		} else {
			in.PowerState = strconv.Itoa(*s.PowerInt)
		}
	}
	for net, addrs := range s.Addresses {
		for _, a := range addrs {
			if a.Addr == "" {
				continue
			}
			v := a.Version
			if v == 0 {
				v = 4
			}
			in.Addresses = append(in.Addresses, InstanceAddress{
				NetworkName: net, Address: a.Addr, Type: a.Type, IPVersion: v,
			})
		}
	}
	return in
}

// imageID copes with nova answering two ways.
//
// A booted-from-image server has image as an object with an id; one booted from
// a volume has it as an empty string. Decoding into a struct would fail on the
// second and lose every VM in the deployment along with it.
func imageID(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	id, _ := m["id"].(string)
	return id
}

// parseNovaTime reads nova's timestamps, which are ISO-8601 with or without a
// zone depending on the field and the release.
func parseNovaTime(s string) time.Time {
	if s = strings.TrimSpace(s); s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05.000000"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
