package store

import (
	"context"
	"testing"
)

// The state vocabulary is the same four words hosts use, enforced the same way.
// A typo reaching this column would make a farm's declared state unreadable by
// anything that switches on it.
// Integration — needs VCTL_TEST_DSN.
func TestDeploymentStateRefusesAnUnknownWord(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "state-farm-a"
	seedInstanceFarm(t, st, farm)

	if err := st.SetDeploymentState(ctx, farm, "down", ""); err == nil {
		t.Fatal("a word outside the vocabulary was accepted")
	}
	if err := st.SetDeploymentState(ctx, farm, StateBroken, "nova 500"); err != nil {
		t.Fatalf("SetDeploymentState: %v", err)
	}
	for _, d := range mustDeployments(t, st) {
		if d.ID == farm {
			if d.State != StateBroken || d.StateNote != "nova 500" {
				t.Errorf("state = %q/%q", d.State, d.StateNote)
			}
			if d.StateChangedAt == nil {
				t.Error("state_changed_at was not set")
			}
			return
		}
	}
	t.Fatalf("%s not in the deployments listing", farm)
}

// Re-declaring the same state must not reset the age. Somebody reads that age
// to decide how stale a fault is, and a reconciler or a repeated command would
// otherwise keep it permanently fresh.
// Integration — needs VCTL_TEST_DSN.
func TestRedeclaringTheSameStateKeepsItsAge(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "state-farm-b"
	seedInstanceFarm(t, st, farm)

	if err := st.SetDeploymentState(ctx, farm, StateBroken, "first"); err != nil {
		t.Fatalf("first: %v", err)
	}
	var first *string
	for _, d := range mustDeployments(t, st) {
		if d.ID == farm && d.StateChangedAt != nil {
			s := d.StateChangedAt.String()
			first = &s
		}
	}
	if first == nil {
		t.Fatal("no state_changed_at after the first declaration")
	}
	if err := st.SetDeploymentState(ctx, farm, StateBroken, "same state, new note"); err != nil {
		t.Fatalf("second: %v", err)
	}
	for _, d := range mustDeployments(t, st) {
		if d.ID != farm {
			continue
		}
		if d.StateChangedAt.String() != *first {
			t.Error("re-declaring the same state reset its age")
		}
		if d.StateNote != "same state, new note" {
			t.Errorf("note = %q, want the new one — only the age is sticky", d.StateNote)
		}
	}
}

// Changing the state does move the age, or "broken for a month" could never
// become "broken for a minute" after a real change.
// Integration — needs VCTL_TEST_DSN.
func TestChangingTheStateMovesItsAge(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "state-farm-c"
	seedInstanceFarm(t, st, farm)

	if err := st.SetDeploymentState(ctx, farm, StateBroken, ""); err != nil {
		t.Fatalf("first: %v", err)
	}
	var first string
	for _, d := range mustDeployments(t, st) {
		if d.ID == farm && d.StateChangedAt != nil {
			first = d.StateChangedAt.String()
		}
	}
	if err := st.SetDeploymentState(ctx, farm, StateActive, ""); err != nil {
		t.Fatalf("second: %v", err)
	}
	for _, d := range mustDeployments(t, st) {
		if d.ID == farm && d.StateChangedAt.String() == first {
			t.Error("changing the state did not move its age")
		}
	}
}

// A farm can be marked broken before anything has successfully collected from
// it — which is exactly when somebody wants to.
// Integration — needs VCTL_TEST_DSN.
func TestStateCanBeDeclaredBeforeAnythingIsCollected(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const farm = "state-farm-new"
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM openstack_deployments WHERE id=$1`, farm)
	})

	if err := st.SetDeploymentState(ctx, farm, StateBroken, "declared before first collection"); err != nil {
		t.Fatalf("SetDeploymentState: %v", err)
	}
	for _, d := range mustDeployments(t, st) {
		if d.ID == farm && d.State == StateBroken {
			return
		}
	}
	t.Fatal("the deployment row was not created")
}

func mustDeployments(t *testing.T, st *Store) []Deployment {
	t.Helper()
	ds, err := st.Deployments(context.Background())
	if err != nil {
		t.Fatalf("Deployments: %v", err)
	}
	return ds
}
