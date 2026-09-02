package openstackapi

import "testing"

// Glance catalogs usually carry the unversioned root, but the same both-shapes
// defence Keystone needed costs nothing here — and the limit has to be in the
// URL, because Glance pages at 25 by default and this call exists for the
// complete id-to-name map.
func TestImagesURLHandlesBothCatalogShapes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://glance:9292", "https://glance:9292/v2/images?limit=1000"},
		{"https://glance:9292/", "https://glance:9292/v2/images?limit=1000"},
		{"https://glance:9292/v2", "https://glance:9292/v2/images?limit=1000"},
	} {
		if got := imagesURL(tc.in); got != tc.want {
			t.Errorf("imagesURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
