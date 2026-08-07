package membership

import (
	"slices"
	"testing"
)

// nova names hosts its own way, and shorter than the inventory in more than one
// way. The third case is why this exists: incheon names its hosts aio01/gpu01
// while the inventory qualifies them by site, and matching only exact and short
// names left all seven local-only — the deployment disowned every machine in it.
func TestMatchHostsPairsAcrossAnInventoryPrefix(t *testing.T) {
	local := []string{"incheon-aio01", "incheon-aio02", "incheon-gpu01"}
	control := []string{"aio01", "aio02", "gpu01"}

	pairs, ambiguous := MatchHosts(local, control)

	for inv, nova := range map[string]string{
		"incheon-aio01": "aio01", "incheon-aio02": "aio02", "incheon-gpu01": "gpu01",
	} {
		if pairs[inv] != nova {
			t.Errorf("%s paired with %q, want %q", inv, pairs[inv], nova)
		}
	}
	if len(ambiguous) != 0 {
		t.Errorf("ambiguous = %v, want none", ambiguous)
	}
}

// A name that fits several inventory hosts is refused, not guessed. Picking one
// would be an inventory claiming a machine on the strength of a resemblance.

func TestMatchHostsRefusesAnAmbiguousName(t *testing.T) {
	local := []string{"incheon-aio01", "seoul-aio01"}
	control := []string{"aio01"}

	pairs, ambiguous := MatchHosts(local, control)

	if len(pairs) != 0 {
		t.Errorf("pairs = %v, want none — the name fits two hosts", pairs)
	}
	if !slices.Contains(ambiguous, "aio01") {
		t.Errorf("ambiguous = %v, want the name reported", ambiguous)
	}
}

// An exact match must win before any looser rule can take the host.

func TestMatchHostsPrefersTheExactName(t *testing.T) {
	local := []string{"aio01", "incheon-aio01"}
	control := []string{"aio01"}

	pairs, _ := MatchHosts(local, control)

	if pairs["aio01"] != "aio01" {
		t.Errorf("pairs = %v, want the exact name to win", pairs)
	}
	if _, taken := pairs["incheon-aio01"]; taken {
		t.Errorf("pairs = %v — the suffix rule stole a host that had an exact match", pairs)
	}
}

// The boundary is required. Without it "u01" would match "sre-gpu01", and a
// name that merely ends in the same letters is not the same machine.

func TestMatchHostsRequiresASeparatorBeforeTheSuffix(t *testing.T) {
	pairs, _ := MatchHosts([]string{"sre-gpu01"}, []string{"u01"})

	if len(pairs) != 0 {
		t.Errorf("pairs = %v — matched on letters rather than on a name", pairs)
	}
}

// The domain-suffix case still works.

func TestMatchHostsStillPairsAcrossADomain(t *testing.T) {
	pairs, _ := MatchHosts([]string{"sre-srv-0059"}, []string{"sre-srv-0059.internal.example"})

	if pairs["sre-srv-0059"] != "sre-srv-0059.internal.example" {
		t.Errorf("pairs = %v, want the qualified nova name paired", pairs)
	}
}

// A farm's name and region are things a person set. The reconciler knows the
// endpoint and nothing else, so writing EXCLUDED unconditionally overwrote them
// with the empty strings it was not carrying — a farm named today was anonymous
// again six hours later, and nothing said so.
// Integration — needs VCTL_TEST_DSN.
