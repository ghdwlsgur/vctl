package openstackapi

import (
	"context"
	"errors"
	"strings"
)

// errNoImageEndpoint mirrors errNoIdentityEndpoint: a nil error with a nil map
// would read as "this deployment has no images".
var errNoImageEndpoint = errors.New("no image endpoint in the service catalog")

// imagesURL builds the image listing path from a catalog entry. Glance
// catalogs usually carry the unversioned root, but the same both-shapes
// defence Keystone needed costs nothing here.
//
// The limit is in the URL because Glance — unlike Keystone — pages its
// listing at 25 by default, and the whole point of this call is the complete
// id-to-name map.
func imagesURL(base string) string {
	base = strings.TrimSuffix(strings.TrimRight(base, "/"), "/v2")
	return base + "/v2/images?limit=1000"
}

// imageLimit bounds how many images one lookup will take, across pages, for
// the same reason the project listing has a ceiling: this runs inside a
// collector with a memory cap.
const imageLimit = 5000

// imagePages bounds how many `next` links are followed. With the limit above
// this is never the binding constraint on a real deployment; it exists so a
// misbehaving endpoint that keeps handing out next-links cannot hold the
// collector in a loop.
const imagePages = 10

// ImageNames maps image id to the name people call it by.
//
// Nova reports a VM's image as a bare uuid and Glance is the only place the
// name exists. The name is worth a call of its own: it says what OS a VM was
// built from, which is what implies the login user a connection should fall
// back to when root is refused.
//
// Best effort by contract, like ProjectNames: a caller that cannot resolve
// names carries on with the ids.
func (c *Client) ImageNames(ctx context.Context) (map[string]string, error) {
	var last error
	for _, e := range preferInternal(c.images) {
		out, err := c.imagesFrom(ctx, e.url)
		if err != nil {
			last = err
			continue
		}
		return out, nil
	}
	if last == nil {
		last = errNoImageEndpoint
	}
	return nil, last
}

func (c *Client) imagesFrom(ctx context.Context, base string) (map[string]string, error) {
	out := map[string]string{}
	url := imagesURL(base)
	for page := 0; page < imagePages && url != ""; page++ {
		var body struct {
			Images []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"images"`
			Next string `json:"next"`
		}
		if err := c.getJSON(ctx, url, &body); err != nil {
			return nil, err
		}
		for _, im := range body.Images {
			if len(out) >= imageLimit {
				return out, nil
			}
			if im.ID != "" && im.Name != "" {
				out[im.ID] = im.Name
			}
		}
		// The next link is a path relative to the service root, not a URL.
		url = ""
		if body.Next != "" {
			url = strings.TrimSuffix(strings.TrimRight(base, "/"), "/v2") + body.Next
		}
	}
	return out, nil
}
