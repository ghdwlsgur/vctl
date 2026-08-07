package cli

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/openstack"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// The judging lives in internal/openstack and is tested there. What is left
// here is rendering, so these check what a reader sees rather than what was
// decided.

func assessed(hosts []store.OpenStackHost, in openstack.Input) openstack.Assessment {
	in.Hosts = hosts
	if in.ID == "" {
		in.ID = "172.16.0.10:5000"
	}
	return openstack.Assess(in)
}

func aioHost(name string, roles []string, active []string, release, conf string) store.OpenStackHost {
	return store.OpenStackHost{
		Hostname: name, Detected: true, Roles: roles, ActiveRoles: active, Confidence: conf,
		Components: map[string]store.CapabilityComponent{
			"nova-compute": {Version: release, Active: true, Service: true},
		},
	}
}

// A section whose every host already appeared carries no new facts, only the
// role's membership. Rendering it as a tree buried the sections that said
// something under ones that repeated "also controller".
func TestFarmShowCollapsesAllRepeatSections(t *testing.T) {
	a := assessed([]store.OpenStackHost{
		aioHost("aio-01", []string{"controller", "compute", "identity"},
			[]string{"controller", "compute", "identity"}, "2025.1", store.ConfidenceConfirmed),
		aioHost("gpu-01", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
	}, openstack.Input{})

	var buf bytes.Buffer
	renderFarmShow(&buf, a, time.Now())
	out := buf.String()

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
	if !strings.Contains(out, "gpu-01") {
		t.Errorf("compute lost the host that introduces it:\n%s", out)
	}
}

// A down role is marked on the host and counted in the heading, and the section
// keeps its size — the deployment did not shrink.
func TestFarmShowMarksOutageWithoutShrinkingTheSection(t *testing.T) {
	a := assessed([]store.OpenStackHost{
		aioHost("n1", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
		aioHost("n2", []string{"compute"}, nil, "2025.1", store.ConfidenceConfirmed),
	}, openstack.Input{})

	var buf bytes.Buffer
	renderFarmShow(&buf, a, time.Now())
	out := buf.String()
	if !strings.Contains(out, "compute") || !strings.Contains(out, "1 down") {
		t.Errorf("the outage was not counted in the heading:\n%s", out)
	}
	if !strings.Contains(out, "n1") || !strings.Contains(out, "n2") {
		t.Errorf("a down host was dropped from the section:\n%s", out)
	}
}

// Drift is the question this view usually exists to answer, and the good news
// is stated too.
func TestFarmShowStatesDriftAndItsAbsence(t *testing.T) {
	drift := assessed([]store.OpenStackHost{
		aioHost("a", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
		aioHost("b", []string{"compute"}, []string{"compute"}, "2024.2", store.ConfidenceConfirmed),
	}, openstack.Input{})
	var buf bytes.Buffer
	renderFarmShow(&buf, drift, time.Now())
	if !strings.Contains(buf.String(), "drift") {
		t.Errorf("two releases were not reported as drifting:\n%s", buf.String())
	}

	same := assessed([]store.OpenStackHost{
		aioHost("a", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
	}, openstack.Input{})
	buf.Reset()
	renderFarmShow(&buf, same, time.Now())
	out := buf.String()
	if strings.Contains(out, "drift") || !strings.Contains(out, "all 1") {
		t.Errorf("a single-release farm did not say so plainly:\n%s", out)
	}
}

// Anomalies go in one block. Scattered through the sections they are each a
// footnote; together they answer "what is wrong with this farm".
func TestFarmShowGathersAnomalies(t *testing.T) {
	gone := time.Now().Add(-72 * time.Hour)
	a := assessed([]store.OpenStackHost{
		aioHost("n1", []string{"compute"}, nil, "2025.1", store.ConfidenceLocalOnly),
	}, openstack.Input{
		Ghosts: []store.ControlHost{{NovaHostname: "sre-svr-0032", FirstSeenAt: gone}},
	})

	var buf bytes.Buffer
	renderFarmShow(&buf, a, time.Now())
	out := buf.String()
	if !strings.Contains(out, "anomalies") {
		t.Fatalf("no anomaly block:\n%s", out)
	}
	if !strings.Contains(out, "sre-svr-0032") {
		t.Errorf("the ghost host is not in the block:\n%s", out)
	}
}

// A deployment named before anything reported renders as an answer, not as an
// empty tree that reads like a rendering fault — and it still says nothing has
// reconciled it.
func TestFarmShowSaysWhenNothingHasReported(t *testing.T) {
	a := openstack.Assess(openstack.Input{ID: "10.0.0.9:5000", Name: "new-farm"})

	var buf bytes.Buffer
	renderFarmShow(&buf, a, time.Now())
	out := buf.String()
	if !strings.Contains(out, "no hosts have reported") {
		t.Errorf("an empty deployment did not say so:\n%s", out)
	}
	if !strings.Contains(out, "never") {
		t.Errorf("an unreconciled deployment did not say so:\n%s", out)
	}
}

// A farm that looks settled and has been failing since is the case the two
// timestamps exist to separate.
func TestFarmShowReportsFailingSinceTheLastSuccess(t *testing.T) {
	success := time.Now().Add(-2 * time.Hour)
	run := store.ReconcileRun{
		StartedAt: time.Now().Add(-10 * time.Minute), SucceededAt: &success,
		LastError: "keystone unreachable", Complete: true,
	}
	a := assessed([]store.OpenStackHost{
		aioHost("n1", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
	}, openstack.Input{Run: &run, StaleAfter: 13 * time.Hour})

	var buf bytes.Buffer
	renderFarmShow(&buf, a, time.Now())
	out := buf.String()
	if !strings.Contains(out, "failing since") {
		t.Errorf("a farm failing since its last success did not say so:\n%s", out)
	}
}

// VMs are counted per host, which is the join the whole chain rests on.
func TestFarmShowCountsVMsPerHost(t *testing.T) {
	a := assessed([]store.OpenStackHost{
		aioHost("gpu01", []string{"compute"}, []string{"compute"}, "2025.1", store.ConfidenceConfirmed),
	}, openstack.Input{Instances: []store.Instance{
		{InstanceID: "u1", HypervisorHostname: "gpu01"},
		{InstanceID: "u2", HypervisorHostname: "gpu01"},
	}})

	var buf bytes.Buffer
	renderFarmShow(&buf, a, time.Now())
	if !strings.Contains(buf.String(), "2 VMs") {
		t.Errorf("VMs were not counted against the host:\n%s", buf.String())
	}
}

// collectAssessment takes an id and nothing else about the deployment.
//
// It used to take the farmChoice the selector built and read the name, region
// and state off it — values from before the snapshot — while the note came from
// the snapshot itself. The signature is the guard: with only an id to work
// from, there is nothing pre-snapshot left to read.
func TestCollectAssessmentTakesOnlyAnID(t *testing.T) {
	fn := reflect.TypeOf(collectAssessment)
	if fn.NumIn() != 4 {
		t.Fatalf("collectAssessment takes %d args, want (ctx, store, id, now)", fn.NumIn())
	}
	if got := fn.In(2).Kind(); got != reflect.String {
		t.Errorf("the deployment argument is %s, want a bare id — anything richer is read before the snapshot", got)
	}
}
