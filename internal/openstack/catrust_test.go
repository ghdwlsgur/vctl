package openstack

import (
	"slices"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/hoststatus"
	"github.com/ghdwlsgur/vctl/internal/store"
)

func metadataHost(name, vendordata string) store.OpenStackHost {
	h := host(name, []string{"controller"}, []string{"controller"}, "2025.1", store.ConfidenceConfirmed)
	h.Details = map[string]string{"vendordata": vendordata, "vendordata_service": "nova-metadata"}
	return h
}

// A VM's metadata request lands on whichever host the VIP picks, so a farm is
// only as onboarded as its weakest metadata service. Reporting the best answer
// would call a coin toss "on".
func TestAFarmIsAsOnboardedAsItsWeakestMetadataHost(t *testing.T) {
	a := Assess(Input{ID: "f", Hosts: []store.OpenStackHost{
		metadataHost("c1", hoststatus.VendordataOn),
		metadataHost("c2", hoststatus.VendordataOn),
		metadataHost("c3", hoststatus.VendordataOff),
	}})
	if a.CATrust.State != hoststatus.VendordataOff {
		t.Fatalf("state = %q, want %q — two of three is not on", a.CATrust.State, hoststatus.VendordataOff)
	}
	if got := a.CATrust.Hosts["c3"]; got != hoststatus.VendordataOff {
		t.Errorf("the odd host out is not named: %v", a.CATrust.Hosts)
	}
}

// Compute nodes have nothing to say about this. Counting them would make every
// farm read as half-configured forever.
func TestOnlyMetadataHostsCount(t *testing.T) {
	compute := host("cmp", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed)
	a := Assess(Input{ID: "f", Hosts: []store.OpenStackHost{
		metadataHost("c1", hoststatus.VendordataOn), compute,
	}})
	if a.CATrust.State != hoststatus.VendordataOn {
		t.Fatalf("state = %q, want on", a.CATrust.State)
	}
	if _, ok := a.CATrust.Hosts["cmp"]; ok {
		t.Errorf("a compute node was folded in: %v", a.CATrust.Hosts)
	}
}

// A farm nobody has onboarded yet is a backlog item, not a fault. Reporting it
// would put a permanent red line under every farm somebody has not got to.
func TestOffIsNotAnAnomaly(t *testing.T) {
	a := Assess(Input{ID: "f", Hosts: []store.OpenStackHost{metadataHost("c1", hoststatus.VendordataOff)}})
	if slices.Contains(kinds(a), AnomalyCATrust) {
		t.Fatalf("off raised an anomaly: %v", kinds(a))
	}
}

// The half-states are not stages on the way to "on". Each is a specific mistake
// that this fleet has actually made, and each has a consequence worth naming.
func TestHalfInstalledIsAnAnomaly(t *testing.T) {
	for _, tc := range []struct{ state, mustSay string }{
		{hoststatus.VendordataNoFile, "fail to start"},
		{hoststatus.VendordataNoConfig, "empty vendor_data.json"},
	} {
		a := Assess(Input{ID: "f", Hosts: []store.OpenStackHost{metadataHost("c1", tc.state)}})
		if !slices.Contains(kinds(a), AnomalyCATrust) {
			t.Fatalf("%s raised no anomaly: %v", tc.state, kinds(a))
		}
		var detail string
		for _, x := range a.Anomalies {
			if x.Kind == AnomalyCATrust {
				detail = x.Detail
			}
		}
		if !strings.Contains(detail, tc.mustSay) {
			t.Errorf("%s: detail %q does not say what goes wrong (%q)", tc.state, detail, tc.mustSay)
		}
	}
}

// config-without-file outranks everything: it is the one that stops a container
// from starting, so a farm with one of those and two clean hosts must lead with
// it rather than with the merely-unconfigured host.
func TestTheContainerBreakingStateWins(t *testing.T) {
	a := Assess(Input{ID: "f", Hosts: []store.OpenStackHost{
		metadataHost("c1", hoststatus.VendordataOff),
		metadataHost("c2", hoststatus.VendordataNoFile),
		metadataHost("c3", hoststatus.VendordataOn),
	}})
	if a.CATrust.State != hoststatus.VendordataNoFile {
		t.Fatalf("state = %q, want %q", a.CATrust.State, hoststatus.VendordataNoFile)
	}
}

// A farm nothing has probed for this says nothing, rather than "off". The two
// are different answers and rendering the first as the second would report
// every farm as unconfigured the moment the probe is deployed but has not run.
func TestNoMetadataHostMeansNoAnswer(t *testing.T) {
	compute := host("cmp", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed)
	a := Assess(Input{ID: "f", Hosts: []store.OpenStackHost{compute}})
	if a.CATrust.State != "" {
		t.Fatalf("state = %q, want empty", a.CATrust.State)
	}
}
