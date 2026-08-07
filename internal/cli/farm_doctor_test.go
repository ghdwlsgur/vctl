package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/openstackapi"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// doctor must not be able to make a farm worse.
//
// It is the command somebody reaches for when a deployment is already
// misbehaving, and "diagnostic" is exactly the word people use for the tool
// they run without thinking about what it writes. Read rather than trusted: the
// shared assertion walks the file and fails on any call that records anything.
func TestFarmDoctorWritesNothing(t *testing.T) {
	assertReadsOnly(t, "openstack_farm_doctor.go", "doctor")
}

// A missing credential field is a different problem from a missing credential,
// and the fix is different too.
func TestMissingCredFieldsNamesWhatIsAbsent(t *testing.T) {
	got := missingCredFields(openstackapi.Credentials{AuthURL: "https://x", Username: "u"})
	joined := strings.Join(got, ",")
	for _, want := range []string{"password", "project_name"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing fields = %v, want %s named", got, want)
		}
	}
	if strings.Contains(joined, "auth_url") {
		t.Errorf("missing fields = %v, want the ones that are set left out", got)
	}
	if len(missingCredFields(openstackapi.Credentials{
		AuthURL: "a", Username: "b", Password: "c", ProjectName: "d",
	})) != 0 {
		t.Error("a complete credential was reported as incomplete")
	}
}

// Vault and the OpenStack SDK return errors several lines long. Dropping one
// into a key/value row breaks the alignment for every row after it, which is
// how a diagnostic becomes harder to read than the log it replaced.
func TestDoctorFlattensMultiLineErrors(t *testing.T) {
	in := "no credentials (Error making API request.\n\nURL: GET https://x\nCode: 403\n)"
	got := oneLine(in)
	if strings.Contains(got, "\n") {
		t.Errorf("oneLine left a newline: %q", got)
	}
	for _, want := range []string{"403", "https://x"} {
		if !strings.Contains(got, want) {
			t.Errorf("oneLine dropped %q: %q", want, got)
		}
	}
}

// The checks are what somebody reads; each has to name itself and say what came
// back.
func TestDoctorRendersEveryCheck(t *testing.T) {
	var buf bytes.Buffer
	renderFarmDoctor(&buf, farmChoice{ID: "10.0.0.1:5000", Name: "lab-a"}, []farmCheck{
		{Name: "Credentials", State: ui.StateOK, Detail: "admin at https://10.0.0.1:5000"},
		{Name: "Nova services", State: ui.StateFail, Detail: "403 — controllers would not be listed"},
	})
	out := buf.String()
	for _, want := range []string{"lab-a", "10.0.0.1:5000", "Credentials", "Nova services", "controllers would not be listed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}
