package cmdkit

import (
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func TestInventoryHostCompletionLeavesOutRetiredHosts(t *testing.T) {
	servers := []store.Server{
		{Hostname: "sre-svr-0001", DC: "seoul"},
		{Hostname: "sre-svr-0002", DC: "seoul", State: store.StateMaintenance},
		{Hostname: "sre-svr-0003", DC: "seoul", State: store.StateRetired},
	}
	got := inventoryHostCompletions(servers, "sre-")
	if v := values(got); len(v) != 2 {
		t.Fatalf("got %v, want the two hosts that are not retired", v)
	}
	if !strings.Contains(got[1], store.StateMaintenance) {
		t.Errorf("a host in maintenance should say so: %q", got[1])
	}
}

// value and values mirror the cli package's test helpers: what a completion
// would put on the command line, dropping the description the shell only
// displays.
func value(candidate string) string {
	v, _, _ := strings.Cut(candidate, "\t")
	return v
}

func values(candidates []string) []string {
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, value(c))
	}
	return out
}
