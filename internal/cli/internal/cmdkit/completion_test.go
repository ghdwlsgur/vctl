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

// A description is display text and the value is a protocol field. cobra splits
// them on a tab and the shell splits candidates on newlines, so a VM named with
// either — nova accepts both — would move the boundary.
func TestCandidateFlattensWhatWouldBreakTheProtocol(t *testing.T) {
	got := Candidate("id", "na\tme\nfarm")
	if strings.Count(got, "\t") != 1 {
		t.Errorf("description tab survived: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("description newline survived: %q", got)
	}
	if value(got) != "id" {
		t.Errorf("value became %q", value(got))
	}
	if Candidate("id", "") != "id" {
		t.Errorf("an empty description should leave no separator, got %q", Candidate("id", ""))
	}
}

func TestByPositionAsksADifferentQuestionPerArgument(t *testing.T) {
	first := StaticCompletions("farm-a")
	second := StaticCompletions("active", "retired")
	fn := ByPosition(first, second)

	got, _ := fn(nil, nil, "")
	if len(got) != 1 || got[0] != "farm-a" {
		t.Fatalf("first argument got %v", got)
	}
	got, _ = fn(nil, []string{"farm-a"}, "")
	if len(got) != 2 {
		t.Fatalf("second argument got %v, want the states", got)
	}
	// Past the end there is no question left to answer.
	if got, _ = fn(nil, []string{"farm-a", "active"}, ""); len(got) != 0 {
		t.Fatalf("third argument got %v, want nothing", got)
	}
}
