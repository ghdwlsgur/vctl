package store

import (
	"context"
	"strings"
	"testing"
)

func TestStateOrActiveTreatsEmptyAsActive(t *testing.T) {
	// Rows written before the column existed, and snapshots captured by an older
	// binary, both arrive with an empty state. They are active hosts, not an
	// unknown fifth thing, and every renderer has to agree on that.
	if got := StateOrActive(""); got != StateActive {
		t.Errorf("StateOrActive(\"\") = %q, want %q", got, StateActive)
	}
	if got := StateOrActive(StateBroken); got != StateBroken {
		t.Errorf("StateOrActive(broken) = %q", got)
	}
}

func TestValidStateAcceptsOnlyTheDeclaredSet(t *testing.T) {
	for _, s := range HostStates {
		if !ValidState(s) {
			t.Errorf("ValidState(%q) = false", s)
		}
	}
	// "down" and "up" are observation's words, not the operator's. Accepting
	// them here would be the start of the two vocabularies merging.
	for _, s := range []string{"", "down", "up", "stale", "ACTIVE"} {
		if ValidState(s) {
			t.Errorf("ValidState(%q) = true", s)
		}
	}
}

// New hosts are active without anyone saying so, and the column reads back
// through the listing. Integration — needs VCTL_TEST_DSN.
func TestSetStateRoundTrips(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "state-host-01"

	_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
	if _, err := st.Insert(ctx, Server{
		Hostname: host, IP: "198.51.100.21", Port: 22, User: "rocky", DC: "test-dc", CARole: "sre-core",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() { _, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host) })

	read := func() string {
		t.Helper()
		rows, err := st.ListInventory(ctx, "")
		if err != nil {
			t.Fatalf("ListInventory: %v", err)
		}
		for _, r := range rows {
			if r.Hostname == host {
				return r.State
			}
		}
		t.Fatalf("%s missing from the listing", host)
		return ""
	}

	if got := read(); got != StateActive {
		t.Errorf("a freshly inserted host reads as %q, want %q", got, StateActive)
	}

	for _, want := range HostStates {
		ok, err := st.SetState(ctx, host, want)
		if err != nil {
			t.Fatalf("SetState(%q): %v", want, err)
		}
		if !ok {
			t.Fatalf("SetState(%q) matched no row", want)
		}
		if got := read(); got != want {
			t.Errorf("after SetState(%q) the listing reads %q", want, got)
		}
	}

	// Get reads the same column through the other select path. The two column
	// lists are maintained separately, so a state that survives one and not the
	// other is exactly the drift worth catching.
	sv, err := st.Get(ctx, host)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if sv.State != StateRetired {
		t.Errorf("Get returned state %q, want the value the listing shows", sv.State)
	}
}

// The database constrains the column, so an unknown value has to be refused
// rather than stored and rendered as a blank cell.
// Integration — needs VCTL_TEST_DSN.
func TestSetStateRejectsAWordTheSchemaWouldNotTake(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "state-host-02"

	_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
	if _, err := st.Insert(ctx, Server{
		Hostname: host, IP: "198.51.100.22", Port: 22, User: "rocky", DC: "test-dc", CARole: "sre-core",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	t.Cleanup(func() { _, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host) })

	_, err := st.SetState(ctx, host, "down")
	if err == nil {
		t.Fatal(`SetState accepted "down"`)
	}
	if !strings.Contains(err.Error(), StateBroken) {
		t.Errorf("error %q does not list the states that would work", err)
	}

	// And the schema itself refuses, so a writer that skips SetState still cannot
	// land a value the renderers do not know how to draw.
	if _, err := st.pool.Exec(ctx,
		`UPDATE servers SET state='down' WHERE hostname=$1`, host); err == nil {
		t.Error("the servers_state_check constraint did not reject a raw bad value")
	}
}
