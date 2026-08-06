package openstackapi

import (
	"context"
	"errors"
	"strings"
)

// errNoIdentityEndpoint is returned when the catalog named no Keystone. It
// should not happen — a token came from one — but a nil error with a nil map
// would read as "this deployment has no projects".
var errNoIdentityEndpoint = errors.New("no identity endpoint in the service catalog")

// projectsURL builds the project listing path from a catalog entry.
//
// Catalogs differ on whether the identity URL already carries /v3. Appending it
// blindly produces /v3/v3 on half the fleet and a 404; stripping and re-adding
// it works for both shapes.
func projectsURL(base string) string {
	base = strings.TrimSuffix(strings.TrimRight(base, "/"), "/v3")
	return base + "/v3/projects"
}

// projectLimit bounds how many projects one lookup will take.
//
// A ceiling rather than none, for the same reason the instance listing has one:
// this runs inside a status collector with a memory cap, and an endpoint that
// keeps answering must not be able to turn that into an outage. Well above any
// deployment here.
const projectLimit = 5000

// ProjectNames maps project id to the name people call it by.
//
// Nova reports a VM's owner as a bare uuid and nothing else. That is the right
// thing to store — it is the identifier, and names change — but it is unreadable
// in a listing, and "which team owns this VM" is most of why anyone looks a VM
// up. Keystone is the only place the name exists.
//
// Needs an admin credential, the same one the instance listing already needs for
// all_tenants. A caller without one gets an error and should carry on with the
// ids: a VM listing without names is worse than one with them and much better
// than none.
func (c *Client) ProjectNames(ctx context.Context) (map[string]string, error) {
	var last error
	for _, e := range preferInternal(c.identities) {
		out, err := c.projectsFrom(ctx, e.url)
		if err != nil {
			last = err
			continue
		}
		return out, nil
	}
	if last == nil {
		last = errNoIdentityEndpoint
	}
	return nil, last
}

func (c *Client) projectsFrom(ctx context.Context, base string) (map[string]string, error) {
	var page struct {
		Projects []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"projects"`
	}
	// v3 is not always in the catalog URL — some catalogs carry the versioned
	// root and some the unversioned one — so ask for the path that works either
	// way rather than guessing and getting a 404 on half the fleet.
	if err := c.getJSON(ctx, projectsURL(base), &page); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(page.Projects))
	for i, p := range page.Projects {
		if i >= projectLimit {
			break
		}
		if p.ID != "" && p.Name != "" {
			out[p.ID] = p.Name
		}
	}
	return out, nil
}
