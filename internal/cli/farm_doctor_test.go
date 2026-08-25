package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/openstack/doctor"
)

// doctor must not be able to make a farm worse.
//
// This file still holds the full *store.Store through withStore, so the
// walker keeps guarding it. The diagnosis itself moved to
// internal/openstack/doctor, where no walker is needed: its ports expose
// exactly ForFarm and ReconcileRuns, so a write would not compile.
func TestFarmDoctorWritesNothing(t *testing.T) {
	assertReadsOnly(t, "openstack_farm_doctor.go", "doctor")
}

// The checks are what somebody reads; each has to name itself and say what came
// back.
func TestDoctorRendersEveryCheck(t *testing.T) {
	var buf bytes.Buffer
	renderFarmDoctor(&buf, farmChoice{ID: "10.0.0.1:5000", Name: "lab-a"}, []doctor.Check{
		{Name: "Credentials", Severity: doctor.OK, Detail: "admin at https://10.0.0.1:5000"},
		{Name: "Nova services", Severity: doctor.Fail, Detail: "403 — controllers would not be listed"},
	})
	out := buf.String()
	for _, want := range []string{"lab-a", "10.0.0.1:5000", "Credentials", "Nova services", "controllers would not be listed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}
