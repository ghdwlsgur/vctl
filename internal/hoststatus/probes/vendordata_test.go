package probes

import (
	"os"
	"path/filepath"
	"testing"
)

// kollaService lays out one Kolla service directory under a test root.
func kollaService(t *testing.T, root, service string, configured, file bool) {
	t.Helper()
	dir := filepath.Join(root, "etc", "kolla", service)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "[DEFAULT]\ndebug = False\ntransport_url = rabbit://openstack:hunter2@10.0.0.1:5672//\n\n[api]\n"
	if configured {
		conf += vendordataKey + " = /etc/nova/vendordata.json\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "nova.conf"), []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if file {
		if err := os.WriteFile(filepath.Join(dir, "vendordata.json"), []byte(`{"cloud-init":"x"}`), 0o660); err != nil {
			t.Fatal(err)
		}
	}
}

// Which service answers instance metadata is the thing this fleet got wrong for
// a month. nova-metadata is its own service on newer releases and absent on
// older ones, so it is derived from what is on the host — never assumed.
func TestTheMetadataServiceIsDerivedNotAssumed(t *testing.T) {
	t.Run("nova-metadata wins when it exists", func(t *testing.T) {
		root := t.TempDir()
		kollaService(t, root, "nova-api", true, true) // configured, but not the one that answers
		kollaService(t, root, "nova-metadata", false, false)
		state, service := (&OpenStack{root: root}).vendordataState()
		if service != "nova-metadata" {
			t.Fatalf("service = %q, want nova-metadata", service)
		}
		if state != VendordataOff {
			t.Errorf("state = %q, want off — nova-api being configured is not the answer", state)
		}
	})

	t.Run("nova-api answers when there is no nova-metadata", func(t *testing.T) {
		root := t.TempDir()
		kollaService(t, root, "nova-api", true, true)
		state, service := (&OpenStack{root: root}).vendordataState()
		if service != "nova-api" || state != VendordataOn {
			t.Fatalf("got %q/%q, want nova-api/on", service, state)
		}
	})
}

// The two half-states are the mistakes, and telling them apart is the point:
// one stops the container from starting, the other serves an empty document.
func TestHalfInstalledStatesAreDistinct(t *testing.T) {
	for _, tc := range []struct {
		name                string
		configured, present bool
		want                string
	}{
		{"both", true, true, VendordataOn},
		{"neither", false, false, VendordataOff},
		{"config only", true, false, VendordataNoFile},
		{"file only", false, true, VendordataNoConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			kollaService(t, root, "nova-metadata", tc.configured, tc.present)
			if state, _ := (&OpenStack{root: root}).vendordataState(); state != tc.want {
				t.Errorf("state = %q, want %q", state, tc.want)
			}
		})
	}
}

// A zero-byte file deploys, mounts, parses as nothing and grants nothing. It
// must not read as "on".
func TestAnEmptyPayloadIsNotOn(t *testing.T) {
	root := t.TempDir()
	kollaService(t, root, "nova-metadata", true, false)
	dir := filepath.Join(root, "etc", "kolla", "nova-metadata")
	if err := os.WriteFile(filepath.Join(dir, "vendordata.json"), nil, 0o660); err != nil {
		t.Fatal(err)
	}
	if state, _ := (&OpenStack{root: root}).vendordataState(); state != VendordataNoFile {
		t.Errorf("state = %q, want %q for a zero-byte payload", state, VendordataNoFile)
	}
}

// A host that serves no metadata API is not missing anything. Saying "off"
// there would put a finding on every compute node in the fleet.
func TestAHostWithNoMetadataServiceSaysNothing(t *testing.T) {
	root := t.TempDir()
	kollaService(t, root, "nova-compute", false, false)
	state, service := (&OpenStack{root: root}).vendordataState()
	if state != "" || service != "" {
		t.Errorf("got %q/%q, want both empty", state, service)
	}
}
