package cli

import (
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The warning has to fire on a machine identity and stay quiet on a person.
//
// The first version compared the token's method against the configured one, and
// that is the wrong question: `vctl login` uses OIDC on this fleet even where
// the config says userpass, so a perfectly good session was reported as broken
// — with the claim "ssh, edit and reconcile will not work" printed directly
// above a line reporting the SSH CA read had succeeded.
//
// What separates the two is the entity, not the method. Measured: the AppRole
// token and the person's token carried the *same* token policy
// (`default, vctl-user`); only the person's carried identity policies from
// group membership.
func TestMachineIdentityIsWhatDistinguishesTheTwo(t *testing.T) {
	for _, tc := range []struct {
		method string
		want   bool
	}{
		{"approle", true},
		{"kubernetes", true},
		{"AppRole", true}, // case is not part of the statement
		{"oidc", false},   // what `vctl login` actually produces
		{"userpass", false},
		{"", false},
	} {
		if got := machineIdentity(tc.method); got != tc.want {
			t.Errorf("machineIdentity(%q) = %v, want %v", tc.method, got, tc.want)
		}
	}
}

func TestAgentSummarySeparatesReportingStaleAndUnmanagedHosts(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	servers := []store.ServerWithStatus{
		{Status: &store.ServerStatus{LastSeenAt: now.Add(-time.Minute)}},
		{Status: &store.ServerStatus{LastSeenAt: now.Add(-statusFreshnessWindow - time.Minute)}},
		{},
		{},
	}

	summary := summarizeAgents(servers, now)
	if summary.Reporting != 1 || summary.Stale != 1 || summary.Unmanaged != 2 {
		t.Fatalf("summary = %+v, want 1 reporting, 1 stale, 2 unmanaged", summary)
	}
	if got := summary.Text(); got != "1 reporting · 1 stale · 2 unmanaged" {
		t.Fatalf("summary text = %q", got)
	}
	if summary.State() != ui.StateWarn {
		t.Error("a stale managed agent must warn")
	}

	healthy := summarizeAgents([]store.ServerWithStatus{
		{Status: &store.ServerStatus{LastSeenAt: now}},
		{}, // unmanaged inventory is neutral, not a failed agent
	}, now)
	if healthy.State() != ui.StateOK {
		t.Errorf("one reporting plus one unmanaged = %v, want OK", healthy.State())
	}
}
