package cli

import (
	"strings"
	"testing"
)

// The shape of wg-standby-failover.sh --status is a contract between two
// repositories (the script ships from the VyOS image catalog). Pin it here so a
// change on that side fails a test instead of silently rendering empty cells.
const failoverStatusOnPrimary = `iface=wg0 active=primary primary_hs_age=12s standby_hs_age=8s down_after=180s up_for=300s
state: ACTIVE_STATE=primary since=2026-09-12 21:00:00 primary_fresh_since=-`

const failoverStatusOnStandbyHeld = `iface=wg1 active=standby primary_hs_age=999999s standby_hs_age=3s down_after=180s up_for=300s
HOLD: /etc/wireguard/failover.hold exists — automatic switching is off
state: ACTIVE_STATE=standby since=2026-09-12 21:05:00 primary_fresh_since=-`

func TestParseFailoverStatusOnPrimary(t *testing.T) {
	s := parseFailoverStatus("sre-lb", failoverStatusOnPrimary)

	if !s.Installed || s.Err != "" {
		t.Fatalf("installed=%v err=%q, want installed with no error", s.Installed, s.Err)
	}
	if s.Iface != "wg0" || s.Active != "primary" {
		t.Fatalf("iface=%q active=%q, want wg0/primary", s.Iface, s.Active)
	}
	if s.PrimaryAge != 12 || s.StandbyAge != 8 {
		t.Fatalf("ages = %d/%d, want 12/8", s.PrimaryAge, s.StandbyAge)
	}
	if s.DownAfter != 180 || s.UpFor != 300 {
		t.Fatalf("thresholds = %d/%d, want 180/300", s.DownAfter, s.UpFor)
	}
	if s.Hold {
		t.Fatal("hold = true, want false")
	}
	if s.Since != "2026-09-12 21:00:00" {
		t.Fatalf("since = %q, want the timestamp without the next key", s.Since)
	}
	if !s.healthy() {
		t.Fatal("healthy = false, want true on the primary with both hubs answering")
	}
}

// status and --dry-run are asked for together, so a row carries both where
// traffic is and the remote's reasoning about it.
func TestParseFailoverStatusKeepsTheRemotesDecision(t *testing.T) {
	out := failoverStatusOnStandbyHeld + "\n" +
		"decision: primary back (22s), waiting 0/300s before failback (active=standby primary_age=22s standby_age=37s)"

	s := parseFailoverStatus("gw-0047", out)

	if !strings.HasPrefix(s.Decision, "primary back (22s)") {
		t.Fatalf("decision = %q, want the script's own verdict", s.Decision)
	}
	if s.Active != "standby" {
		t.Fatalf("active = %q, want the --status line to still win", s.Active)
	}
}

func TestParseFailoverStatusOnStandbyWithHold(t *testing.T) {
	s := parseFailoverStatus("gw-0047", failoverStatusOnStandbyHeld)

	if s.Active != "standby" || !s.Hold {
		t.Fatalf("active=%q hold=%v, want standby/true", s.Active, s.Hold)
	}
	if got := s.age(s.PrimaryAge); got != "never" {
		t.Fatalf("primary age = %q, want never for the script's sentinel", got)
	}
	if got := s.age(s.StandbyAge); got != "3s" {
		t.Fatalf("standby age = %q, want 3s", got)
	}
	if s.healthy() {
		t.Fatal("healthy = true, want false while carrying transit on the standby")
	}
}

func TestParseFailoverStatusReportsAMissingAgent(t *testing.T) {
	s := parseFailoverStatus("sre-srv-0056", failoverAbsentMark+"\n")

	if s.Installed {
		t.Fatal("installed = true, want false for a host without the script")
	}
	if s.Err != "" {
		t.Fatalf("err = %q, want empty: a host that never had the agent is not a failure", s.Err)
	}
	if row := failoverRow(s); row[2] != "no agent" {
		t.Fatalf("row verdict = %q, want \"no agent\"", row[2])
	}
}

func TestParseFailoverStatusFlagsUnrecognisedOutput(t *testing.T) {
	if s := parseFailoverStatus("h", "bash: line 1: wg: command not found"); s.Err == "" {
		t.Fatal("err = empty, want an error for output that is not a status line")
	}
}

// The remotes are a mix of root and sudo logins; escalation is decided per host.
func TestFailoverShellEscalatesOnlyForNonRoot(t *testing.T) {
	if got := sudoFor("root"); got != "" {
		t.Fatalf("sudoFor(root) = %q, want empty", got)
	}
	if got := sudoFor("rocky"); got != "sudo -n " {
		t.Fatalf("sudoFor(rocky) = %q, want non-interactive sudo", got)
	}
	cmd := failoverShell(sudoFor("rocky"), "--failover")
	if !strings.Contains(cmd, "sudo -n "+failoverScript+" --failover") {
		t.Fatalf("command = %q, want the escalated script call", cmd)
	}
	if !strings.Contains(cmd, failoverAbsentMark) {
		t.Fatalf("command = %q, want the missing-agent sentinel branch", cmd)
	}
}

// A remote sitting happily on the primary whose standby has never answered is
// the quiet failure this tally exists to name: every other column looks fine,
// and it would ride out an outage instead of switching.
func TestFailoverTallyNamesRemotesWithoutStandbyCover(t *testing.T) {
	var tally failoverTally
	tally.add(parseFailoverStatus("sre-lb", failoverStatusOnPrimary))
	tally.add(parseFailoverStatus("gw-0047", `iface=wg2 active=primary primary_hs_age=9s standby_hs_age=999999s down_after=180s up_for=300s`))
	tally.add(parseFailoverStatus("gw-0048", failoverAbsentMark))
	tally.add(failoverStatus{Host: "gone", Err: "dial tcp: i/o timeout"})

	if tally.total != 4 {
		t.Fatalf("total = %d, want 4", tally.total)
	}
	if tally.uncovered != 1 {
		t.Fatalf("uncovered = %d, want 1 — the wg2 remote whose standby never handshook", tally.uncovered)
	}
	if tally.ready != 1 {
		t.Fatalf("ready = %d, want 1: only the remote with both hubs answering", tally.ready)
	}
	if tally.absent != 1 || tally.failed != 1 {
		t.Fatalf("absent=%d failed=%d, want 1/1", tally.absent, tally.failed)
	}
	if err := tally.report(); err == nil {
		t.Fatal("report() = nil, want an error while a remote is unreachable")
	}
}
