package cli

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func farmChoicesFixture() []farmChoice {
	return []farmChoice{
		{ID: "172.16.0.245:5000", Hosts: 7, Roles: "compute 5 · controller 3"},
		{ID: "172.16.0.10:5000", Name: "incheon", Region: "kr-inc-1", Hosts: 7, Roles: "compute 7"},
	}
}

// An endpoint is not something a person recognises. Whoever is naming farms is
// looking at addresses they may never have seen, and what identifies a
// deployment to them is what is in it.
func TestFarmPickerShowsWhatEachDeploymentContains(t *testing.T) {
	labels := farmPickLabels(farmChoicesFixture())

	if !strings.Contains(labels[0], "7 hosts") || !strings.Contains(labels[0], "controller 3") {
		t.Errorf("label = %q, want the size and shape that identify it", labels[0])
	}
	if !strings.Contains(labels[1], "incheon") {
		t.Errorf("label = %q, want the existing name shown so it can be recognised", labels[1])
	}
}

// Naming by the name it already has must work, or renaming means looking up an
// endpoint the listing no longer shows.
func TestFarmIsFoundByIDOrByExistingName(t *testing.T) {
	farms := farmChoicesFixture()

	if i := indexOfFarm(farms, "172.16.0.10:5000"); i != 1 {
		t.Errorf("lookup by id = %d", i)
	}
	if i := indexOfFarm(farms, "incheon"); i != 1 {
		t.Errorf("lookup by existing name = %d", i)
	}
	if i := indexOfFarm(farms, "nope"); i != -1 {
		t.Errorf("unknown deployment resolved to %d", i)
	}
}

// Both arguments given is the non-interactive path, and it must not open a form
// — that is what makes the command usable from a script.
func TestFarmNameWithBothArgumentsNeedsNoTerminal(t *testing.T) {
	id, name, region, err := resolveFarmName(farmChoicesFixture(), "172.16.0.245:5000", "seoul-a", "kr-seoul-1")
	if err != nil {
		t.Fatalf("resolveFarmName: %v", err)
	}
	if id != "172.16.0.245:5000" || name != "seoul-a" || region != "kr-seoul-1" {
		t.Errorf("got %q/%q/%q", id, name, region)
	}
}

// A name for a deployment that does not exist is a typo, not a new farm. The
// farm's identity comes from its Keystone, so accepting an arbitrary id here
// would create one nothing can ever reconcile.
func TestFarmNameRefusesAnUnknownDeployment(t *testing.T) {
	if _, _, _, err := resolveFarmName(farmChoicesFixture(), "10.0.0.9:5000", "typo", ""); err == nil {
		t.Fatal("an unknown deployment was accepted")
	}
}

// Whitespace around a name typed at a shell must not become part of it.
func TestFarmNameIsTrimmed(t *testing.T) {
	_, name, _, err := resolveFarmName(farmChoicesFixture(), "172.16.0.245:5000", "  seoul-a  ", "")
	if err != nil || name != "seoul-a" {
		t.Errorf("name = %q, %v", name, err)
	}
}

// The listing prefers the name once one exists — that is the whole point of
// setting it.
func TestListingPrefersTheDeploymentName(t *testing.T) {
	h := store.OpenStackHost{Farm: "172.16.0.10:5000", FarmName: "incheon"}
	if got := farmLabel(h); got != "incheon" {
		t.Errorf("farmLabel = %q, want the name", got)
	}
	h.FarmName = ""
	if got := farmLabel(h); got != "172.16.0.10:5000" {
		t.Errorf("farmLabel = %q, want the endpoint when unnamed", got)
	}
}

// Every command that takes a deployment resolves it the same way, because rules
// that differ per command are rules nobody can hold in their head.
func TestResolveFarmAcceptsIdsAndUniqueNames(t *testing.T) {
	farms := []farmChoice{
		{ID: "172.16.0.150:5000", Name: "seoul-b"},
		{ID: "172.16.0.10:5000", Name: "incheon"},
		{ID: "192.168.201.130:5000"}, // never named
	}

	for _, tc := range []struct{ selector, want string }{
		{"172.16.0.150:5000", "172.16.0.150:5000"},
		// The name the listing itself prints. Matching ids only meant this
		// returned nothing and rendered it as an empty fleet.
		{"seoul-b", "172.16.0.150:5000"},
		{"SEOUL-B", "172.16.0.150:5000"},
		{"192.168.201.130:5000", "192.168.201.130:5000"},
	} {
		got, err := resolveFarm(farms, tc.selector)
		if err != nil {
			t.Errorf("resolveFarm(%q): %v", tc.selector, err)
			continue
		}
		if got.ID != tc.want {
			t.Errorf("resolveFarm(%q) = %q, want %q", tc.selector, got.ID, tc.want)
		}
	}
}

// Two deployments sharing a display name is not something to settle by
// position. `farm state` and `farm name` change things, and picking whichever
// sorted first would change the wrong one without saying so.
func TestResolveFarmRefusesAnAmbiguousName(t *testing.T) {
	farms := []farmChoice{
		{ID: "10.0.0.1:5000", Name: "lab"},
		{ID: "10.0.0.2:5000", Name: "lab"},
	}

	_, err := resolveFarm(farms, "lab")
	if err == nil {
		t.Fatal("an ambiguous name resolved to one deployment; a mutating command would hit the wrong farm")
	}
	// Both candidates, so the next command can be typed without guessing.
	for _, id := range []string{"10.0.0.1:5000", "10.0.0.2:5000"} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("error = %q, missing candidate %s", err, id)
		}
	}
}

// An id is the identifier. A different deployment happening to be *named* that
// does not get to intercept it.
func TestResolveFarmPrefersAnExactIdOverSomebodyElsesName(t *testing.T) {
	farms := []farmChoice{
		{ID: "10.0.0.2:5000", Name: "10.0.0.1:5000"},
		{ID: "10.0.0.1:5000", Name: "incheon"},
	}

	got, err := resolveFarm(farms, "10.0.0.1:5000")
	if err != nil {
		t.Fatalf("resolveFarm: %v", err)
	}
	if got.ID != "10.0.0.1:5000" {
		t.Errorf("resolved to %q, want the deployment whose id it is", got.ID)
	}
}

// "There is no such farm" and "this farm has no hosts" are different sentences,
// and an empty listing says the second one. A selector that matches nothing has
// to stop.
func TestResolveFarmRefusesAnUnknownSelector(t *testing.T) {
	_, err := resolveFarm([]farmChoice{{ID: "10.0.0.1:5000", Name: "incheon"}}, "typo-farm")
	if err == nil {
		t.Fatal("an unknown selector resolved; the caller would render an empty listing as an answer")
	}
	if !strings.Contains(err.Error(), "typo-farm") {
		t.Errorf("error = %q, want it to name what was not found", err)
	}
}
