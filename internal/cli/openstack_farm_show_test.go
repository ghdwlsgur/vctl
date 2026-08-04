package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func showFixture() []store.OpenStackHost {
	mk := func(name string, roles []string, release string, conf string) store.OpenStackHost {
		h := osHost(name, "172.16.0.10:5000", roles...)
		h.ActiveRoles = roles
		h.Confidence = conf
		if release != "" {
			h.Components = map[string]store.CapabilityComponent{
				"nova-compute": {Version: release, Active: true, Service: true},
			}
		}
		return h
	}
	return []store.OpenStackHost{
		mk("aio-01", []string{"controller", "compute", "identity"}, "2025.1", store.ConfidenceConfirmed),
		mk("aio-02", []string{"controller", "compute"}, "2025.1", store.ConfidenceConfirmed),
		mk("gpu-01", []string{"compute"}, "2024.2", store.ConfidenceLocalOnly),
		// A different farm's host: must not leak into this view.
		func() store.OpenStackHost { h := osHost("other-01", "10.9.9.9:5000", "compute"); return h }(),
	}
}

func showPick() farmChoice {
	return farmChoice{ID: "172.16.0.10:5000", Name: "incheon", Region: "kr-inc-1"}
}

// The whole point of the view: roles become sections a reader walks top-down,
// control plane first, and only this farm's hosts are in them.
func TestFarmViewSectionsAreOrderedControlPlaneFirst(t *testing.T) {
	v := buildFarmView(showPick(), showFixture())

	if v.Total != 3 {
		t.Fatalf("total = %d, want only this farm's hosts", v.Total)
	}
	var order []string
	for _, s := range v.Sections {
		order = append(order, s.Role)
	}
	if len(order) < 2 || order[0] != "controller" || order[1] != "compute" {
		t.Errorf("section order = %v, want the control plane first", order)
	}
	for _, s := range v.Sections {
		for _, m := range s.Hosts {
			if m.Hostname == "other-01" {
				t.Error("another farm's host leaked into the view")
			}
		}
	}
}

// A host repeated across sections must not repeat its facts. An all-in-one
// deployment where every host is controller+compute+network would otherwise
// read as three times its size.
func TestFarmViewMarksRepeatsInsteadOfRestatingThem(t *testing.T) {
	v := buildFarmView(showPick(), showFixture())

	var compute *farmSection
	for i := range v.Sections {
		if v.Sections[i].Role == "compute" {
			compute = &v.Sections[i]
		}
	}
	if compute == nil {
		t.Fatal("no compute section")
	}
	for _, m := range compute.Hosts {
		switch m.Hostname {
		case "aio-01", "aio-02":
			if m.AlsoIn != "controller" {
				t.Errorf("%s AlsoIn = %q, want the section it already appeared in", m.Hostname, m.AlsoIn)
			}
		case "gpu-01":
			if m.AlsoIn != "" {
				t.Errorf("gpu-01 AlsoIn = %q — compute is its first section", m.AlsoIn)
			}
		}
	}
}

// Release drift is the question this view usually exists to answer, and it has
// to be one line rather than something assembled by scanning a column.
func TestFarmViewCountsReleaseDrift(t *testing.T) {
	v := buildFarmView(showPick(), showFixture())

	if v.Releases["2025.1"] != 2 || v.Releases["2024.2"] != 1 {
		t.Errorf("releases = %v", v.Releases)
	}
	var buf bytes.Buffer
	renderFarmShow(&buf, v)
	if !strings.Contains(buf.String(), "drift") {
		t.Errorf("a two-release farm was not reported as drifting:\n%s", buf.String())
	}
}

// A single-release farm must say so plainly — "no drift" is the good news.
func TestFarmViewSaysWhenThereIsNoDrift(t *testing.T) {
	hosts := showFixture()[:2] // both 2025.1
	v := buildFarmView(showPick(), hosts)

	var buf bytes.Buffer
	renderFarmShow(&buf, v)
	out := buf.String()
	if strings.Contains(out, "drift") {
		t.Errorf("a single-release farm was reported as drifting:\n%s", out)
	}
	if !strings.Contains(out, "all 2") {
		t.Errorf("the release line does not say it covers every host:\n%s", out)
	}
}

// Membership that rests on anything weaker than confirmation is called out with
// the confidence that says why — the same rule every other view follows.
func TestFarmViewCallsOutUnsettledMembership(t *testing.T) {
	v := buildFarmView(showPick(), showFixture())

	if v.Confirmed != 2 || v.Total != 3 {
		t.Errorf("confirmed = %d/%d", v.Confirmed, v.Total)
	}
	if len(v.Unsettled) != 1 || !strings.Contains(v.Unsettled[0], "gpu-01") ||
		!strings.Contains(v.Unsettled[0], store.ConfidenceLocalOnly) {
		t.Errorf("unsettled = %v, want the host and its confidence", v.Unsettled)
	}
}

// A deployment named before anything reported renders as an answer, not as an
// empty tree that reads like a rendering fault.
func TestFarmViewSaysWhenNothingHasReported(t *testing.T) {
	v := buildFarmView(farmChoice{ID: "10.0.0.9:5000", Name: "new-farm"}, showFixture())

	var buf bytes.Buffer
	renderFarmShow(&buf, v)
	if !strings.Contains(buf.String(), "no hosts have reported") {
		t.Errorf("an empty deployment did not say so:\n%s", buf.String())
	}
}

// A section whose every host already appeared carries no new facts, only the
// role's membership. Rendering it as a tree buried the two sections that said
// something under seven that repeated "also controller".
func TestFarmShowCollapsesAllRepeatSections(t *testing.T) {
	v := buildFarmView(showPick(), showFixture())

	var buf bytes.Buffer
	renderFarmShow(&buf, v)
	out := buf.String()

	// identity holds only aio-01, already shown under controller — one line,
	// with the membership inline rather than a one-branch tree.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "identity") {
			if !strings.Contains(line, "aio-01") {
				t.Errorf("identity line = %q, want the membership inline", line)
			}
			if strings.Contains(line, "└─") || strings.Contains(line, "├─") {
				t.Errorf("identity line = %q — an all-repeat section kept its tree", line)
			}
		}
	}
	// compute introduces gpu-01, so it stays a tree.
	if !strings.Contains(out, "└─ gpu-01") && !strings.Contains(out, "├─ gpu-01") {
		t.Errorf("compute lost its tree:\n%s", out)
	}
}

// A compute node whose nova-compute is down is still a compute node. The
// section keeps its size — the deployment did not shrink — and the outage is
// marked on the host and counted in the heading.
func TestFarmShowKeepsTheRoleAndMarksTheOutage(t *testing.T) {
	hosts := showFixture()
	for i := range hosts {
		if hosts[i].Hostname == "gpu-01" {
			hosts[i].ActiveRoles = nil // deployed compute, nothing running
		}
	}
	v := buildFarmView(showPick(), hosts)

	var compute *farmSection
	for i := range v.Sections {
		if v.Sections[i].Role == "compute" {
			compute = &v.Sections[i]
		}
	}
	if compute == nil {
		t.Fatal("no compute section")
	}
	if len(compute.Hosts) != 3 {
		t.Errorf("compute has %d hosts, want 3 — a down node is still a compute node", len(compute.Hosts))
	}
	if compute.Down != 1 {
		t.Errorf("down = %d, want 1", compute.Down)
	}

	var buf bytes.Buffer
	renderFarmShow(&buf, v)
	out := buf.String()
	if !strings.Contains(out, "1 down") {
		t.Errorf("the heading does not count the outage:\n%s", out)
	}
	if !strings.Contains(out, "down") {
		t.Errorf("the host is not marked:\n%s", out)
	}
}

// With everything up nothing is marked, so the marking means something.
func TestFarmShowMarksNothingWhenEverythingIsUp(t *testing.T) {
	v := buildFarmView(showPick(), showFixture())

	for _, sec := range v.Sections {
		if sec.Down != 0 {
			t.Errorf("%s down = %d, want 0", sec.Role, sec.Down)
		}
	}
}
