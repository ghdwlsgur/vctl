package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// The last successful reconcile is what makes every other number on the row
// worth reading. A farm nothing has ever confirmed still shows host and VM
// counts, and they are the probe's guesses.
func TestFarmListLeadsWithWhetherAnythingConfirmedIt(t *testing.T) {
	now := time.Now()
	recent := now.Add(-time.Minute)
	old := now.Add(-farmStaleWindow - time.Hour)

	var buf bytes.Buffer
	renderFarmList(&buf, []farmSummary{
		{ID: "10.0.0.1:5000", Name: "fresh-farm", Hosts: 3, VMs: 9, Reconciled: &recent},
		{ID: "10.0.0.2:5000", Name: "old-farm", Hosts: 2, VMs: 4, Reconciled: &old},
		{ID: "10.0.0.3:5000", Name: "new-farm", Hosts: 1},
	}, now)

	out := buf.String()
	if !strings.Contains(out, "never") {
		t.Errorf("a farm nothing ever reconciled does not say so:\n%s", out)
	}
	for _, h := range []string{"NAME", "ENDPOINT", "HOSTS", "VMS", "RECONCILED"} {
		if !strings.Contains(out, h) {
			t.Errorf("no %s header:\n%s", h, out)
		}
	}
}

func TestFarmListAdaptsToANarrowTerminal(t *testing.T) {
	now := time.Now()
	recent := now.Add(-time.Minute)
	var buf bytes.Buffer
	renderFarmListWidth(&buf, []farmSummary{{
		ID: "192.168.201.115:5000", Name: "a-long-openstack-farm-name", Region: "incheon",
		State: "active", Hosts: 7, VMs: 65, Reconciled: &recent,
	}}, now, 72)

	out := stripANSI(buf.String())
	for _, want := range []string{"NAME", "STATE", "HOSTS", "VMS", "RECONCILED"} {
		if !strings.Contains(out, want) {
			t.Errorf("narrow farm list dropped essential column %q:\n%s", want, out)
		}
	}
	for _, optional := range []string{"ENDPOINT", "REGION"} {
		if strings.Contains(out, optional) {
			t.Errorf("narrow farm list retained optional column %q:\n%s", optional, out)
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n") {
		if width := lipgloss.Width(line); width > 72 {
			t.Errorf("line width %d exceeds 72: %q", width, line)
		}
	}
}

// A deployment nobody has named is still a deployment. Leaving it out would
// make this listing disagree with `vctl openstack`, which does show it.
func TestFarmListShowsUnnamedDeployments(t *testing.T) {
	var buf bytes.Buffer
	renderFarmList(&buf, []farmSummary{{ID: "10.0.0.9:5000", Hosts: 1}}, time.Now())
	out := buf.String()
	if !strings.Contains(out, "10.0.0.9:5000") {
		t.Errorf("the endpoint is missing:\n%s", out)
	}
	if !strings.Contains(out, "unnamed") {
		t.Errorf("nothing says the deployment has no name:\n%s", out)
	}
}

// The reason a farm is not settling belongs on its row. Reading it out of
// `farm show`, one farm at a time, is how a fleet-wide problem looks like
// several unrelated ones.
func TestFarmListCarriesTheReasonOnTheRow(t *testing.T) {
	now := time.Now()
	at := now.Add(-time.Minute)
	var buf bytes.Buffer
	renderFarmList(&buf, []farmSummary{
		{ID: "a", Name: "failing", Reconciled: &at, LastError: "context deadline exceeded"},
		{ID: "b", Name: "unsettled", Reconciled: &at, Unsettled: 2},
	}, now)

	out := buf.String()
	if !strings.Contains(out, "context deadline exceeded") {
		t.Errorf("the failure is not on the row:\n%s", out)
	}
	if !strings.Contains(out, "2 host(s) unsettled") {
		t.Errorf("unsettled hosts are not counted on the row:\n%s", out)
	}
}

// --fail-on names problems, and an unknown one has to be refused rather than
// silently ignored — a timer configured with a typo would report every run as
// healthy.
func TestFailOnRefusesWhatItDoesNotKnow(t *testing.T) {
	if _, err := parseFailOn("unreachable,warning"); err != nil {
		t.Errorf("known problems rejected: %v", err)
	}
	if got, err := parseFailOn(""); err != nil || got != nil {
		t.Errorf("empty --fail-on = %v, %v; want nothing and no error", got, err)
	}
	_, err := parseFailOn("unreachble")
	if err == nil {
		t.Fatal("a typo was accepted; every run would then look healthy")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error = %q, want it to name the valid choices", err)
	}
}
