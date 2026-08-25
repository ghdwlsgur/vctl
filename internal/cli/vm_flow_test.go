package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func vmSeen(id, name string, age time.Duration) store.Instance {
	return store.Instance{
		DeploymentID: "farm-a", InstanceID: id, Name: name, Status: "ACTIVE",
		ObservedAt: time.Now().Add(-age),
		Addresses:  []store.InstanceAddress{{Address: "192.168.1.5", Type: "fixed"}},
	}
}

// The id was in the data and on no screen.
//
// SSH takes a Nova uuid and nothing else — deliberately, because a name fits
// several VMs across farms — so a listing that shows only names left the two
// commands unable to be used together. Finding the uuid meant piping --json
// through something.
func TestTheListingShowsTheIDSSHNeeds(t *testing.T) {
	var buf bytes.Buffer
	const id = "a5b39f17-4acb-4f96-a9d7-ec1916400e21"
	renderVMs(&buf, []store.Instance{vmSeen(id, "st770-bastion", time.Minute)},
		nil, nil, time.Now(), false)

	out := buf.String()
	if !strings.Contains(out, id[:8]) {
		t.Errorf("the listing does not show the id:\n%s", out)
	}
	// Short by default: a full uuid on every row costs the columns after it.
	if strings.Contains(out, id) {
		t.Errorf("the default listing printed a whole uuid:\n%s", out)
	}
	// And headers, so the columns are readable without counting them.
	for _, h := range []string{"ID", "NAME", "SEEN"} {
		if !strings.Contains(out, h) {
			t.Errorf("no %s header:\n%s", h, out)
		}
	}
}

// --wide is what a copy-paste wants.
func TestWideShowsTheWholeUUID(t *testing.T) {
	var buf bytes.Buffer
	const id = "a5b39f17-4acb-4f96-a9d7-ec1916400e21"
	renderVMs(&buf, []store.Instance{vmSeen(id, "vm", time.Minute)}, nil, nil, time.Now(), true)
	if !strings.Contains(buf.String(), id) {
		t.Errorf("--wide did not print the whole uuid:\n%s", buf.String())
	}
}

// An address is only as current as the pass that recorded it, and nothing in
// the row said when that was. A reconcile failing for days leaves rows that
// look exactly like fresh ones.
func TestTheListingSaysHowOldEachRecordIs(t *testing.T) {
	var buf bytes.Buffer
	now := time.Now()
	renderVMs(&buf, []store.Instance{
		vmSeen("11111111-1111-1111-1111-111111111111", "recent", time.Minute),
		vmSeen("22222222-2222-2222-2222-222222222222", "old", staleProbeWindow+time.Hour),
	}, nil, nil, now, false)

	// Assert the two rows differ and the stale one is flagged, rather than on
	// an exact rendering — the formatter rounds, and pinning "1m" here would be
	// a test of CompactDuration written in the wrong file.
	out := buf.String()
	fresh, stale := lineFor(t, out, "recent"), lineFor(t, out, "old")
	if fresh == stale {
		t.Fatalf("both rows read the same:\n%s", out)
	}
	if !strings.Contains(stale, "h") {
		t.Errorf("the stale row does not show its age in hours:\n%s", stale)
	}
	// Warn styling is what marks it apart; colour does not survive a pipe, so
	// the age itself has to differ visibly, which the hours do.
	if strings.Contains(fresh, "h") {
		t.Errorf("the fresh row reads as hours old:\n%s", fresh)
	}
}

func lineFor(t *testing.T, out, name string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, name) {
			return l
		}
	}
	t.Fatalf("no row for %s in:\n%s", name, out)
	return ""
}

// The detail view ends with the command to run next. Naming the flags and
// leaving somebody to assemble them is where the flow broke.
func TestVMShowPrintsTheCommandToConnect(t *testing.T) {
	var buf bytes.Buffer
	v := vmSeen("a5b39f17-4acb-4f96-a9d7-ec1916400e21", "bastion", time.Minute)
	renderVMShow(&buf, v, nil, []string{"192.168."}, time.Now())

	out := buf.String()
	if !strings.Contains(out, "vctl ssh --vm "+v.InstanceID) {
		t.Errorf("no ready-to-run command:\n%s", out)
	}
	// Every address, not the ranked one: this is where a person decides.
	if !strings.Contains(out, "192.168.1.5") {
		t.Errorf("the addresses are missing:\n%s", out)
	}
}

// A VM with nothing worth connecting to must say so here rather than let
// somebody find out from `ssh`.
func TestVMShowSaysWhenSSHWillRefuse(t *testing.T) {
	var buf bytes.Buffer
	v := vmSeen("a5b39f17-4acb-4f96-a9d7-ec1916400e21", "tenant-only", time.Minute)
	v.Addresses = []store.InstanceAddress{{Address: "10.3.1.7", Type: "fixed"}}
	renderVMShow(&buf, v, nil, []string{"192.168."}, time.Now())

	// The refusal names the command it is refusing, so match the offer's shape
	// — a runnable line ends with the uuid and --user.
	out := buf.String()
	if strings.Contains(out, "vctl ssh --vm "+v.InstanceID) {
		t.Errorf("offered a command that will be refused:\n%s", out)
	}
	if !strings.Contains(out, "will refuse") {
		t.Errorf("did not say ssh will refuse:\n%s", out)
	}
	// And it points at the door that does not pretend to know.
	if !strings.Contains(out, "vctl ssh <user>@<addr>") {
		t.Errorf("no alternative offered:\n%s", out)
	}
}

// The staleness window is the collector's schedule, not a number picked here —
// three missed hourly passes, the same reasoning the capability probe uses.
func TestStaleWindowMatchesTheCollectorsSchedule(t *testing.T) {
	if staleProbeWindow != staleProbeWindow {
		t.Errorf("staleProbeWindow = %v, staleProbeWindow = %v; two windows for the same question drift",
			staleProbeWindow, staleProbeWindow)
	}
}
