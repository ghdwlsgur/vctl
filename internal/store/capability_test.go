package store

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func seedCapabilityHost(t *testing.T, st *Store, host string) {
	t.Helper()
	ctx := context.Background()
	_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
	if _, err := st.Insert(ctx, Server{
		Hostname: host, IP: "198.51.100.90", Port: 22, User: "rocky", DC: "test-dc", CARole: "sre-core",
	}); err != nil {
		t.Fatalf("insert %s: %v", host, err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM server_capabilities WHERE hostname=$1`, host)
		_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
	})
}

// A capability round-trips with its per-component versions intact.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityRoundTrips(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-01"
	seedCapabilityHost(t, st, host)

	in := Capability{
		Hostname: host, Kind: "openstack", Role: "compute", Detected: true,
		Components: map[string]CapabilityComponent{
			"nova-compute": {Version: "31.2.0", Active: true},
			"libvirt":      {Version: "10.0.0", Active: true},
			"qemu":         {Version: "8.2.0"},
		},
		Details: map[string]string{"hypervisor": "kvm", "deployment": "unknown"},
	}
	ok, err := st.ReplaceCapabilities(ctx, host, "openstack", []Capability{in})
	if err != nil || !ok {
		t.Fatalf("ReplaceCapabilities: %v ok=%v", err, ok)
	}

	rows, err := st.Capabilities(ctx, "openstack")
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	var got *Capability
	for i := range rows {
		if rows[i].Hostname == host {
			got = &rows[i]
		}
	}
	if got == nil {
		t.Fatalf("%s not in the listing", host)
	}
	// Per component, because a rolling upgrade leaves them apart for weeks and a
	// single release string could not say which one lagged.
	if got.Components["nova-compute"].Version != "31.2.0" || got.Components["qemu"].Version != "8.2.0" {
		t.Errorf("component versions lost: %+v", got.Components)
	}
	if got.Details["hypervisor"] != "kvm" {
		t.Errorf("details lost: %+v", got.Details)
	}
	if !got.Detected {
		t.Error("detected did not survive")
	}
}

// The write refuses to create inventory, the same way the heartbeat does. A host
// that could file capabilities for a name it does not own could invent a compute
// node, and anything planning maintenance from this would believe it.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityRefusesAnUnknownHost(t *testing.T) {
	st := testStore(t)
	ok, err := st.ReplaceCapabilities(context.Background(), "cap-host-does-not-exist", "openstack",
		[]Capability{{Role: "compute", Detected: true}})
	if err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}
	if ok {
		t.Error("a capability was recorded for a host that is not in the inventory")
	}
}

// A probe that fails must not erase what it last found. Deleting the rows would
// turn a timeout into "this host runs nothing", which reads as a decommission.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityErrorKeepsTheLastKnownFacts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-02"
	seedCapabilityHost(t, st, host)

	if _, err := st.ReplaceCapabilities(ctx, host, "openstack", []Capability{{
		Role: "compute", Detected: true,
		Components: map[string]CapabilityComponent{"nova-compute": {Version: "31.2.0", Active: true}},
	}}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}
	if err := st.RecordCapabilityError(ctx, host, "openstack", "ssh timeout"); err != nil {
		t.Fatalf("RecordCapabilityError: %v", err)
	}

	rows, _ := st.Capabilities(ctx, "openstack")
	for _, r := range rows {
		if r.Hostname != host {
			continue
		}
		if r.LastError != "ssh timeout" {
			t.Errorf("last_error = %q, want the probe's message", r.LastError)
		}
		if !r.Detected || r.Components["nova-compute"].Version != "31.2.0" {
			t.Errorf("the failed probe erased the facts: detected=%v components=%+v", r.Detected, r.Components)
		}
		return
	}
	t.Fatalf("%s disappeared from the listing after a probe error", host)
}

// "Probed and found nothing" is a row; "never probed" is no row. A listing that
// cannot tell them apart reads an unprobed fleet as an empty one.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityRecordsAnAbsentPlatform(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-03"
	seedCapabilityHost(t, st, host)

	if _, err := st.ReplaceCapabilities(ctx, host, "openstack", []Capability{{Role: "none"}}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}
	rows, _ := st.Capabilities(ctx, "openstack")
	for _, r := range rows {
		if r.Hostname == host {
			if r.Detected {
				t.Error("an absent platform was recorded as detected")
			}
			return
		}
	}
	t.Error("an absent platform left no row, so it cannot be told from never having been probed")
}

// The first probe on a host is the one most likely to fail — that is when the
// packaging and permissions are still wrong — and it is the one that had
// nothing to update. An UPDATE-only implementation touched zero rows, returned
// nil, and left the failure with no trace anywhere: the host read exactly like
// one nothing had looked at yet.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityErrorOnAHostWithNoRowsIsStillRecorded(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-04"
	seedCapabilityHost(t, st, host)

	if err := st.RecordCapabilityError(ctx, host, "openstack", "probe timed out"); err != nil {
		t.Fatalf("RecordCapabilityError: %v", err)
	}

	rows, _ := st.Capabilities(ctx, "openstack")
	for _, r := range rows {
		if r.Hostname != host {
			continue
		}
		if r.LastError != "probe timed out" {
			t.Errorf("last_error = %q, want the probe's message", r.LastError)
		}
		if r.Detected {
			t.Error("a failed probe was recorded as having found OpenStack")
		}
		return
	}
	t.Fatal("a failed first probe left no row, so the failure is invisible")
}

// A repeated failure must not accumulate rows or lose the message.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityErrorIsIdempotentOnAHostWithNoRows(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-05"
	seedCapabilityHost(t, st, host)

	for _, msg := range []string{"first failure", "second failure"} {
		if err := st.RecordCapabilityError(ctx, host, "openstack", msg); err != nil {
			t.Fatalf("RecordCapabilityError(%s): %v", msg, err)
		}
	}

	rows, _ := st.Capabilities(ctx, "openstack")
	var n int
	var last string
	for _, r := range rows {
		if r.Hostname == host {
			n++
			last = r.LastError
		}
	}
	if n != 1 {
		t.Errorf("%d rows after two failures, want 1", n)
	}
	if last != "second failure" {
		t.Errorf("last_error = %q, want the most recent failure", last)
	}
}

// The write refuses to create inventory here too. A host that could file an
// error for a name it does not own could invent a machine out of a timeout.
// Integration — needs VCTL_TEST_DSN.
func TestCapabilityErrorRefusesAnUnknownHost(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if err := st.RecordCapabilityError(ctx, "cap-host-nowhere", "openstack", "timeout"); err != nil {
		t.Fatalf("RecordCapabilityError: %v", err)
	}
	rows, _ := st.Capabilities(ctx, "openstack")
	for _, r := range rows {
		if r.Hostname == "cap-host-nowhere" {
			t.Error("an error was recorded for a host that is not in the inventory")
		}
	}
}

// seedCapability plants one capability row with a chosen observation time.
//
// The fold's whole job is deciding which pass is current, so testing it needs
// rows from different passes — which is exactly what ReplaceCapabilities will
// not let a caller do, on purpose. That control belongs to fixtures, not to the
// production API, so it lives here as SQL rather than as a timestamp parameter
// nobody writing an agent should be able to reach for.
func seedCapability(t *testing.T, st *Store, c Capability, at time.Time) {
	t.Helper()
	comps, err := json.Marshal(orEmptyComponents(c.Components))
	if err != nil {
		t.Fatalf("marshal components: %v", err)
	}
	details, err := json.Marshal(orEmptyDetails(c.Details))
	if err != nil {
		t.Fatalf("marshal details: %v", err)
	}
	if _, err := st.pool.Exec(context.Background(), `
		INSERT INTO server_capabilities
			(hostname, kind, role, detected, active, components, details, last_error, observed_at, updated_at)
		SELECT $1,$2,$3,$4,$9,$5::jsonb,$6::jsonb,$7,$8, now()
		WHERE EXISTS (SELECT 1 FROM servers WHERE hostname=$1)
		ON CONFLICT (hostname, kind, role) DO UPDATE SET
			detected=EXCLUDED.detected, active=EXCLUDED.active,
			components=EXCLUDED.components,
			details=EXCLUDED.details, last_error=EXCLUDED.last_error,
			observed_at=EXCLUDED.observed_at, updated_at=now()`,
		c.Hostname, c.Kind, c.Role, c.Detected, string(comps), string(details), c.LastError, at, c.Active); err != nil {
		t.Fatalf("seed capability %s/%s: %v", c.Hostname, c.Role, err)
	}
}

// A pass that fails partway must leave the previous one standing.
//
// Per-role writes tore here. The reader takes the newest observed_at for a host
// and reads every older row as a role the host has stopped holding, so a
// failure between role three and role four left three roles current and the
// rest looking dropped — a controller that "lost" five roles until the next
// hourly pass, which is indistinguishable in the listing from one that really
// did.
// Integration — needs VCTL_TEST_DSN.
func TestAFailedPassLeavesThePreviousOneIntact(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-06"
	seedCapabilityHost(t, st, host)

	full := []Capability{
		{Role: "controller", Detected: true},
		{Role: "compute", Detected: true},
		{Role: "network", Detected: true},
		{Role: "image", Detected: true},
	}
	if _, err := st.ReplaceCapabilities(ctx, host, "openstack", full); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	before := rolesOf(t, st, host)
	if len(before) != 4 {
		t.Fatalf("first pass recorded %v, want four roles", before)
	}

	// Fail the pass on its third role. A cancelled context is how this really
	// arrives: the attempt deadline expires partway through the write.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := st.ReplaceCapabilities(cancelled, host, "openstack", full[:2]); err == nil {
		t.Fatal("a write on a cancelled context reported success")
	}

	if after := rolesOf(t, st, host); len(after) != len(before) {
		t.Errorf("roles = %v after a failed pass, want the previous pass intact %v", after, before)
	}
}

// One pass is one observation, so every role it wrote has to carry the same
// instant. The reader splits current from dropped on exactly this comparison —
// roles a millisecond apart would make the earliest ones look superseded by the
// latest ones from the very same probe.
// Integration — needs VCTL_TEST_DSN.
func TestOnePassStampsEveryRoleWithOneInstant(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-07"
	seedCapabilityHost(t, st, host)

	if _, err := st.ReplaceCapabilities(ctx, host, "openstack", []Capability{
		{Role: "controller", Detected: true},
		{Role: "compute", Detected: true},
		{Role: "network", Detected: true},
	}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}

	var times, passes int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(DISTINCT observed_at), count(DISTINCT pass_id)
		FROM server_capabilities WHERE hostname=$1 AND kind='openstack'`,
		host).Scan(&times, &passes); err != nil {
		t.Fatalf("count: %v", err)
	}
	if times != 1 {
		t.Errorf("one pass wrote %d distinct observation times, want 1", times)
	}
	// The pass number is what the reader now splits on, so it is the one that
	// has to be identical across every role of one probe.
	if passes != 1 {
		t.Errorf("one pass wrote %d distinct pass ids, want 1", passes)
	}
}

// A row from a fast clock can neither pin stale facts nor drag the freshness
// forward with it.
//
// The first half is old: a host is exactly the machine whose clock nobody has
// checked, and one running ahead used to stamp rows every later pass looked
// older than — so the reader kept choosing the stale pass and read every fresh
// role as dropped. Rows like that exist in the fleet, written by older agents,
// so the guard has to hold over rows this code did not write.
//
// The second half is what the pass number bought. Beating the skew used to mean
// out-stamping it, which made the skew permanent: from then on the newest pass
// was always a day in the future and the listing reported an hour-old probe as
// tomorrow's, with nothing on screen to say it was wrong. Ordering by a counter
// leaves the clock alone, so the new pass wins *and* says when it actually ran.
// Integration — needs VCTL_TEST_DSN.
func TestAFutureTimestampCannotPinStaleFactsOrInfectTheNextPass(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-08"
	seedCapabilityHost(t, st, host)

	// What an older agent on a host whose clock is a day fast left behind.
	future := time.Now().Add(24 * time.Hour)
	seedCapability(t, st, Capability{
		Hostname: host, Kind: "openstack", Role: "compute", Detected: true,
	}, future)

	if _, err := st.ReplaceCapabilities(ctx, host, "openstack",
		[]Capability{{Role: "controller", Detected: true}}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}

	var (
		at   time.Time
		pass int64
	)
	if err := st.pool.QueryRow(ctx,
		`SELECT observed_at, pass_id FROM server_capabilities WHERE hostname=$1 AND role='controller'`,
		host).Scan(&at, &pass); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if at.After(future) {
		t.Errorf("new pass stamped %v, past the skewed row at %v — the skew has been inherited "+
			"and every later pass will report the future too", at, future)
	}
	// Loosely, and against the database's own clock rather than this test's:
	// these are two machines and they disagree by milliseconds even on one
	// laptop. A minute is far tighter than the day this is guarding against and
	// far looser than any drift between them.
	if off := at.Sub(time.Now()).Abs(); off > time.Minute {
		t.Errorf("new pass stamped %v, %v away from now — it is carrying somebody else's clock", at, off)
	}
	if pass < 1 {
		t.Errorf("pass_id = %d, want a real pass — 0 is where a failed probe's placeholder sits", pass)
	}

	// And the reader agrees: the new role is what the host holds now, and its
	// age is the age of the pass rather than of the row it replaced.
	got := findOpenStackHost(t, st, host)
	if !containsRole(got.Roles, "controller") {
		t.Errorf("roles = %v, want the newest pass to win", got.Roles)
	}
	if got.ObservedAt.After(future) {
		t.Errorf("the listing reads this host as observed at %v, which is ahead of a clock "+
			"that is already a day fast", got.ObservedAt)
	}
}

func rolesOf(t *testing.T, st *Store, host string) []string {
	t.Helper()
	rows, err := st.Capabilities(context.Background(), "openstack")
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	var out []string
	for _, r := range rows {
		if r.Hostname == host {
			out = append(out, r.Role)
		}
	}
	return out
}

func containsRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// The migration's backfill has to leave every host reading exactly as it did.
//
// It is the one part of this change that touches data nobody can re-derive: a
// pass number wrong by one row flips which roles are current, so a host either
// loses roles it holds or resurrects ones it dropped — and both look like the
// fleet changed rather than like a migration ran.
//
// The migration file itself is executed rather than a copy of its SQL. A copy
// tests the copy, and the statement that runs in production is the one worth
// checking.
// Integration — needs VCTL_TEST_DSN.
func TestTheBackfillNumbersExistingPassesInTheOrderTheyWereAlreadyIn(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-09"
	seedCapabilityHost(t, st, host)

	// Rows in the shape the old writer left: passes told apart by time alone,
	// with no pass number on them.
	old := time.Now().Add(-72 * time.Hour)
	seedCapability(t, st, Capability{
		Hostname: host, Kind: "openstack", Role: "network", Detected: true,
	}, old)
	seedCapability(t, st, Capability{
		Hostname: host, Kind: "openstack", Role: "compute", Detected: true,
	}, time.Now())
	if _, err := st.pool.Exec(ctx,
		`UPDATE server_capabilities SET pass_id=0 WHERE hostname=$1`, host); err != nil {
		t.Fatalf("clear pass ids: %v", err)
	}

	// Undistinguishable until the backfill runs: one number for both passes.
	if got := findOpenStackHost(t, st, host); len(got.Dropped) != 0 {
		t.Fatalf("dropped = %+v before the backfill, want nothing — the fixture is not the "+
			"un-numbered state this is meant to migrate", got.Dropped)
	}

	sql, err := os.ReadFile("migrations/021_capability_pass.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := st.pool.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("run migration: %v", err)
	}

	got := findOpenStackHost(t, st, host)
	if !containsRole(got.Roles, "compute") {
		t.Errorf("roles = %v, want the newer pass's compute", got.Roles)
	}
	if containsRole(got.Roles, "network") {
		t.Errorf("roles = %v — the older pass came back as current", got.Roles)
	}
	if len(got.Dropped) != 1 || got.Dropped[0].Role != "network" {
		t.Errorf("dropped = %+v, want the role the older pass held", got.Dropped)
	}

	// A host still running the old agent during the rollout files a pass that
	// names no pass_id, so it lands on the column default. That pass is newer
	// than everything the backfill numbered and has to read that way — which is
	// the whole reason the history is numbered downward from zero.
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO server_capabilities
			(hostname, kind, role, detected, components, details, last_error, observed_at, updated_at)
		VALUES ($1,'openstack','block-storage',true,'{}','{}','', now(), now())`, host); err != nil {
		t.Fatalf("write as an un-upgraded agent: %v", err)
	}
	if got := findOpenStackHost(t, st, host); !containsRole(got.Roles, "block-storage") {
		t.Errorf("roles = %v — a pass from an agent that has not been upgraded reads as older "+
			"than the rows already here, so every host inverts for the length of the rollout",
			got.Roles)
	}

	// And the pass a later, upgraded probe writes beats both of them.
	if _, err := st.ReplaceCapabilities(ctx, host, "openstack",
		[]Capability{{Role: "controller", Detected: true}}); err != nil {
		t.Fatalf("ReplaceCapabilities: %v", err)
	}
	if got := findOpenStackHost(t, st, host); !containsRole(got.Roles, "controller") ||
		containsRole(got.Roles, "compute") || containsRole(got.Roles, "block-storage") {
		t.Errorf("roles = %v, want only the pass written after the migration", got.Roles)
	}
}

// A row already stamped ahead of the clock is brought back to when the database
// wrote it, so the fleet does not carry the old skew forward under the new
// scheme.
// Integration — needs VCTL_TEST_DSN.
func TestTheMigrationClampsATimestampFromTheFuture(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const host = "cap-host-10"
	seedCapabilityHost(t, st, host)

	future := time.Now().Add(48 * time.Hour)
	seedCapability(t, st, Capability{
		Hostname: host, Kind: "openstack", Role: "compute", Detected: true,
	}, future)

	sql, err := os.ReadFile("migrations/021_capability_pass.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := st.pool.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("run migration: %v", err)
	}

	var at, wrote time.Time
	if err := st.pool.QueryRow(ctx,
		`SELECT observed_at, updated_at FROM server_capabilities WHERE hostname=$1 AND role='compute'`,
		host).Scan(&at, &wrote); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if at.After(wrote) {
		t.Errorf("observed_at %v is still ahead of the write at %v", at, wrote)
	}
	if !at.Equal(wrote) {
		t.Errorf("observed_at = %v, want the time the database wrote the row (%v)", at, wrote)
	}
}
