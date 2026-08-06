package openstackapi

import "testing"

// Catalogs differ on whether the identity URL already carries /v3. Appending it
// blindly gives /v3/v3 and a 404 on half the fleet, which reads as "this farm
// has no projects" rather than as a bug in the path.
func TestProjectsURLHandlesBothCatalogShapes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://keystone:5000", "https://keystone:5000/v3/projects"},
		{"https://keystone:5000/", "https://keystone:5000/v3/projects"},
		{"https://keystone:5000/v3", "https://keystone:5000/v3/projects"},
		{"https://keystone:5000/v3/", "https://keystone:5000/v3/projects"},
	} {
		if got := projectsURL(tc.in); got != tc.want {
			t.Errorf("projectsURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
