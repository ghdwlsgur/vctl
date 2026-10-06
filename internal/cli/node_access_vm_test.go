package cli

import (
	"strings"
	"testing"
)

func TestGatewayHostsCommandOnlyAddsMissingGuestMapping(t *testing.T) {
	got := gatewayHostsCommand("node-access.sre.local", "192.168.201.12")
	for _, want := range []string{
		"getent hosts \"node-access.sre.local\"",
		"192.168.201.12",
		"node-access.sre.local",
		"/etc/hosts",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("gatewayHostsCommand() = %q, missing %q", got, want)
		}
	}
	if strings.Contains(gatewayHostsCommand("", "192.168.201.12"), "/etc/hosts") {
		t.Fatal("gatewayHostsCommand added a mapping without a hostname")
	}
	if strings.Contains(gatewayHostsCommand("node-access.sre.local", ""), "/etc/hosts") {
		t.Fatal("gatewayHostsCommand added a mapping without an address")
	}
}
