package store

import "testing"

// Addresses in these fixtures are RFC 5737 documentation ranges and the
// hostnames are invented: this repository is public.
func statusFor(ips ...string) *ServerStatus { return &ServerStatus{ObservedIPs: ips} }

func TestPrimaryDriftedWhenTheAgentDoesNotSeeTheDialledAddress(t *testing.T) {
	w := ServerWithStatus{
		Server: Server{Hostname: "gw-a", IP: "198.51.100.10"},
		Status: statusFor("198.51.100.11", "203.0.113.4"),
	}

	if !w.PrimaryDrifted() {
		t.Fatal("PrimaryDrifted = false, want true: the dialled address is not one the host has")
	}
}

func TestPrimaryNotDriftedWhenTheAgentSeesIt(t *testing.T) {
	w := ServerWithStatus{
		Server: Server{Hostname: "gw-a", IP: "198.51.100.10"},
		Status: statusFor("198.51.100.10", "203.0.113.4"),
	}

	if w.PrimaryDrifted() {
		t.Fatal("PrimaryDrifted = true, want false")
	}
}

// A masked INET and its bare form are the same address; they reach the two
// sides of this comparison from different columns.
func TestPrimaryNotDriftedAcrossAMaskedAddress(t *testing.T) {
	w := ServerWithStatus{
		Server: Server{Hostname: "gw-a", IP: "198.51.100.10"},
		Status: statusFor("198.51.100.10/32"),
	}

	if w.PrimaryDrifted() {
		t.Fatal("PrimaryDrifted = true, want false: /32 is the same address")
	}
}

// Drift is only meaningful while an agent is reporting. Without one the answer
// is "unknown", and calling that drift would flag most of a fleet that simply
// has no agent installed.
func TestPrimaryNotDriftedWithoutAnAgent(t *testing.T) {
	for name, w := range map[string]ServerWithStatus{
		"no status": {Server: Server{Hostname: "gw-a", IP: "198.51.100.10"}},
		"no observed addresses": {
			Server: Server{Hostname: "gw-a", IP: "198.51.100.10"},
			Status: statusFor(),
		},
		"no primary": {
			Server: Server{Hostname: "gw-a"},
			Status: statusFor("198.51.100.11"),
		},
	} {
		if w.PrimaryDrifted() {
			t.Fatalf("%s: PrimaryDrifted = true, want false", name)
		}
	}
}
