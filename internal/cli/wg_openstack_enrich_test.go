package cli

import (
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func TestWGOpenStackEnrichmentPlacesCollectedVMOnComputeHost(t *testing.T) {
	got := enrichWGAnnotations(
		[]store.WGInterfaceRow{{WGInterface: store.WGInterface{Host: "[surromind]-worker", PublicKey: "K38"}}},
		[]store.Server{{Hostname: "[surromind]-worker", IP: "192.168.10.38"}, {Hostname: "incheon-gpu05", IP: "192.168.10.23"}},
		nil,
		[]store.Instance{{DeploymentID: "farm", Name: "surromind-worker", HypervisorHostname: "gpu05", Addresses: []store.InstanceAddress{{Address: "192.168.10.38", Type: "floating"}}}},
		[]store.OpenStackHost{{Hostname: "incheon-gpu05", Farm: "farm"}},
	)
	if len(got) != 1 {
		t.Fatalf("annotations = %+v", got)
	}
	a := got[0]
	// OpenStack says what machine hosts the endpoint, not what role the endpoint
	// plays in the WireGuard graph. A collected interface remains a gateway so
	// hub selection cannot jump to a different node.
	if a.PublicKey != "K38" || a.Label != "surromind-worker" || a.Kind != "" ||
		a.UnderlayIP != "192.168.10.38" || a.InventoryHost != "[surromind]-worker" ||
		a.ParentHostname != "incheon-gpu05" {
		t.Fatalf("enriched annotation = %+v", a)
	}
}

func TestWGOpenStackEnrichmentCompletesManualAnnotationWithoutOverwritingIt(t *testing.T) {
	manual := store.WGEndpointAnnotation{
		PublicKey: "K76", Label: "operator label", Kind: "vm", UnderlayIP: "192.168.40.76", Note: "keep me",
	}
	got := enrichWGAnnotations(nil,
		[]store.Server{{Hostname: "incheon-gpu03", IP: "192.168.10.16"}},
		[]store.WGEndpointAnnotation{manual},
		[]store.Instance{{DeploymentID: "farm", Name: "gpu-worker-incheon", HypervisorHostname: "gpu03", Addresses: []store.InstanceAddress{{Address: "192.168.40.76", Type: "fixed"}}}},
		[]store.OpenStackHost{{Hostname: "incheon-gpu03", Farm: "farm"}},
	)
	if len(got) != 1 {
		t.Fatalf("annotations = %+v", got)
	}
	a := got[0]
	if a.Label != manual.Label || a.Kind != manual.Kind || a.Note != manual.Note {
		t.Fatalf("manual fields were overwritten: %+v", a)
	}
	if a.ParentHostname != "incheon-gpu03" {
		t.Fatalf("parent = %q, want incheon-gpu03", a.ParentHostname)
	}
}

func TestWGOpenStackEnrichmentSkipsAmbiguousAddress(t *testing.T) {
	got := enrichWGAnnotations(
		[]store.WGInterfaceRow{{WGInterface: store.WGInterface{Host: "vm", PublicKey: "K"}}},
		[]store.Server{{Hostname: "vm", IP: "192.0.2.8"}}, nil,
		[]store.Instance{
			{DeploymentID: "farm-a", Name: "a", Addresses: []store.InstanceAddress{{Address: "192.0.2.8"}}},
			{DeploymentID: "farm-b", Name: "b", Addresses: []store.InstanceAddress{{Address: "192.0.2.8"}}},
		}, nil,
	)
	if len(got) != 0 {
		t.Fatalf("ambiguous address produced annotation: %+v", got)
	}
}
