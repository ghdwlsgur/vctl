package cli

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// The argument guards are what stop a typo from reporting a clean sweep it
// never performed, so they are checked without a database.
func TestWGForgetRefusesHostsItDoesNotHold(t *testing.T) {
	collected := []string{"gw-a", "gw-b"}

	if _, err := wgForgetTargetsFrom(collected, nil, []string{"gw-typo"}, false); err == nil {
		t.Fatal("err = nil, want a refusal for a host with no collected rows")
	} else if !strings.Contains(err.Error(), "gw-typo") {
		t.Fatalf("err = %v, want it to name the host", err)
	}
	if _, err := wgForgetTargetsFrom(collected, nil, nil, false); err == nil {
		t.Fatal("err = nil, want a refusal when neither hosts nor --gone were given")
	}
	if _, err := wgForgetTargetsFrom(collected, nil, []string{"gw-a"}, true); err == nil {
		t.Fatal("err = nil, want a refusal for hosts and --gone together")
	}
	got, err := wgForgetTargetsFrom(collected, nil, []string{"gw-a"}, false)
	if err != nil || len(got) != 1 || got[0] != "gw-a" {
		t.Fatalf("targets = %v, %v; want [gw-a], nil", got, err)
	}
}

// --gone is the case the command exists for: a gateway the inventory dropped
// can never sync again, so nothing else would ever clear its rows.
func TestWGForgetGoneSelectsHostsTheInventoryLost(t *testing.T) {
	collected := []string{"gw-a", "gw-decommissioned", "gw-b"}
	servers := []store.Server{{Hostname: "gw-a"}, {Hostname: "gw-b"}}

	got, err := wgForgetTargetsFrom(collected, servers, nil, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(got) != 1 || got[0] != "gw-decommissioned" {
		t.Fatalf("targets = %v, want only the host the inventory lost", got)
	}
}

func TestWGForgetGoneIsEmptyWhenNothingDrifted(t *testing.T) {
	collected := []string{"gw-a"}
	servers := []store.Server{{Hostname: "gw-a"}}

	got, err := wgForgetTargetsFrom(collected, servers, nil, true)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Fatalf("targets = %v, want none", got)
	}
}

func TestWGForgetCountsTotal(t *testing.T) {
	c := store.WGForgetCounts{Interfaces: 2, Peers: 5, Statuses: 5}
	if c.Total() != 12 {
		t.Fatalf("Total = %d, want 12", c.Total())
	}
}
