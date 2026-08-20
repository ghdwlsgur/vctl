package store

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNullIfEmpty(t *testing.T) {
	if got := nullIfEmpty(""); got != nil {
		t.Errorf(`nullIfEmpty("") = %v, want nil`, got)
	}
	if got := nullIfEmpty("x"); got != "x" {
		t.Errorf(`nullIfEmpty("x") = %v, want "x"`, got)
	}
}

func TestMergeAddresses(t *testing.T) {
	got := mergeAddresses("10.0.0.1", []string{"10.0.0.2", "10.0.0.1", ""}, []string{"10.0.0.2", "192.168.1.9"})
	want := []string{"10.0.0.1", "10.0.0.2", "192.168.1.9"}
	if len(got) != len(want) {
		t.Fatalf("mergeAddresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mergeAddresses[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
	// Primary must always come first even when it also appears in a later set.
	if got[0] != "10.0.0.1" {
		t.Fatalf("primary not first: %v", got)
	}
}

// Sync identifies an existing inventory row by primary IP. If legacy data has
// duplicates, choosing one with LIMIT 1 corrupts whichever row the planner
// happened to return; fail closed until a DBA resolves the ambiguity.
func TestUpsertRejectsAnAmbiguousPrimaryIP(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const ip = "192.0.2.243"
	for _, host := range []string{"duplicate-ip-a", "duplicate-ip-b"} {
		_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host)
		ok, err := st.Insert(ctx, Server{Hostname: host, IP: ip, Port: 22, User: "root", DC: "test", CARole: "sre-core"})
		if err != nil || !ok {
			t.Fatalf("seed %s: ok=%v err=%v", host, ok, err)
		}
		t.Cleanup(func() { _, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, host) })
	}

	err := st.Upsert(ctx, Server{Hostname: "incoming", IP: ip, Port: 22, DC: "test", CARole: "sre-core"})
	if err == nil || !strings.Contains(err.Error(), "multiple servers") {
		t.Fatalf("ambiguous upsert error = %v", err)
	}
}

// PostgreSQL INET equality includes the prefix length. Older inventory can
// therefore contain 192.0.2.10/24 even though vctl treats it as a host address.
// Keep the indexed host-mask path fast without making those rows disappear from
// resolution or causing sync to create a duplicate hostname for the same host.
func TestMaskedINETValuesRemainResolvableAndSyncable(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := "masked-inet-host-" + time.Now().Format("150405.000000")
	incoming := host + "-duplicate"
	_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=ANY($1::text[])`, []string{host, incoming})
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=ANY($1::text[])`, []string{host, incoming})
	})

	if _, err := st.pool.Exec(ctx, `
		INSERT INTO servers (hostname, ip, ssh_port, ssh_user, dc, ca_role, extra_ips)
		VALUES ($1, '192.0.2.244/24'::inet, 22, 'root', 'test', 'sre-core',
		        ARRAY['198.51.100.244/24'::inet])`, host); err != nil {
		t.Fatalf("seed masked server: %v", err)
	}
	if _, err := st.pool.Exec(ctx, `
		INSERT INTO server_status (hostname, observed_ips)
		VALUES ($1, ARRAY['203.0.113.244/24'::inet])`, host); err != nil {
		t.Fatalf("seed masked status: %v", err)
	}

	for _, addr := range []string{"192.0.2.244", "198.51.100.244", "203.0.113.244"} {
		got, candidates, err := st.Resolve(ctx, addr)
		if err != nil || got == nil || got.Hostname != host || len(candidates) != 0 {
			t.Fatalf("Resolve(%s) = server=%v candidates=%v err=%v", addr, got, candidates, err)
		}
	}

	if err := st.Upsert(ctx, Server{
		Hostname: incoming, IP: "192.0.2.244", Port: 2222, DC: "test", CARole: "sre-core",
	}); err != nil {
		t.Fatalf("Upsert masked primary: %v", err)
	}
	var count int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM servers WHERE hostname=ANY($1::text[])`,
		[]string{host, incoming}).Scan(&count); err != nil {
		t.Fatalf("count sync rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("sync created a duplicate for masked primary: count=%d", count)
	}
}

func TestOpenLocalRejectsNonLoopbackHost(t *testing.T) {
	for _, dsn := range []string{
		"postgres://user:pass@db.example.com/vctl",
		"postgres://user:pass@10.0.0.5:5432/vctl",
		// pgx turns a comma-separated list into Fallbacks and dials them in order,
		// so a loopback primary must not smuggle a remote host in behind it.
		"postgres://user:pass@127.0.0.1,db.example.com/vctl",
	} {
		_, err := OpenLocal(context.Background(), dsn)
		if err == nil {
			t.Fatalf("OpenLocal accepted a non-loopback database host: %s", dsn)
		}
		// Assert the guard rejected it rather than the dial failing by luck: an
		// unreachable host errors either way.
		if !strings.Contains(err.Error(), "must be loopback") {
			t.Fatalf("OpenLocal(%s) failed outside the loopback guard: %v", dsn, err)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"127.0.0.53", true},
		{"::1", true},
		{"db.example.com", false},
		{"10.0.0.5", false},
		{"0.0.0.0", false},
		{"/var/run/postgresql", false},
		{"", false},
	} {
		if got := isLoopbackHost(tc.host); got != tc.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// testStore connects to a throwaway Postgres named by VCTL_TEST_DSN and applies
// migrations. Skips when the env var is unset so unit runs need no database.
//
//	VCTL_TEST_DSN=postgres://user:pass@localhost:5432/vctl_test go test ./internal/store/
func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("VCTL_TEST_DSN")
	if dsn == "" {
		t.Skip("VCTL_TEST_DSN not set; skipping DB integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	st := &Store{pool: pool}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}

// TestSessionEventRoundTrip exercises the audit path end to end: record a
// session, ingest events that link by cgroup, and confirm the timeline groups
// them under the right session. Integration — needs VCTL_TEST_DSN.
// freeAddress removes whatever host currently owns addr and arranges for this
// test's own row to go too, so a fixed test address stays reusable across runs.
// Integration tests share one database; leaking a row here breaks the next run
// of this test rather than the current one, which makes it easy to miss.
func freeAddress(t *testing.T, st *Store, addr string) {
	t.Helper()
	ctx := context.Background()
	clear := func() {
		rows, err := st.List(ctx, "")
		if err != nil {
			return
		}
		for _, sv := range rows {
			if sv.IP == addr {
				_, _ = st.Delete(ctx, sv.Hostname)
			}
		}
	}
	clear()
	t.Cleanup(clear)
}

func TestSessionEventRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := "test-host-" + time.Now().Format("150405.000000")
	start := time.Now().UTC().Truncate(time.Second)

	id, err := st.RecordSession(ctx, AuditSession{
		CertSerial: "SER-1", VaultUser: "alice", Hostname: host, LoginUser: "root",
		LeaderPID: 4242, CgroupID: 999, StartedAt: start,
	})
	if err != nil {
		t.Fatalf("RecordSession: %v", err)
	}

	// Idempotent re-record (same host/pid/started) must NOT create a new row —
	// guards against the watch-sessions restart duplication bug.
	id2, err := st.RecordSession(ctx, AuditSession{
		CertSerial: "SER-1", Hostname: host, LoginUser: "root",
		LeaderPID: 4242, CgroupID: 999, StartedAt: start,
	})
	if err != nil || id2 != id {
		t.Fatalf("re-RecordSession = (%d,%v), want (%d,nil)", id2, err, id)
	}

	n, err := st.InsertKernelEvents(ctx, []KernelEvent{
		{Hostname: host, TS: start.Add(time.Second), Kind: "exec", Binary: "/usr/bin/id", CgroupID: 999},
		{Hostname: host, TS: start.Add(2 * time.Second), Kind: "exit", Binary: "/usr/bin/id", CgroupID: 999},
	})
	if err != nil || n != 2 {
		t.Fatalf("InsertKernelEvents = (%d,%v), want (2,nil)", n, err)
	}

	sessions, byID, err := st.SessionTimeline(ctx, "SER-1", 10)
	if err != nil {
		t.Fatalf("SessionTimeline: %v", err)
	}
	if len(sessions) != 1 || sessions[0].VaultUser != "alice" {
		t.Fatalf("sessions = %+v, want 1 (alice)", sessions)
	}
	if got := len(byID[id]); got != 2 {
		t.Fatalf("events linked = %d, want 2", got)
	}

	// Fixture cleanup is deliberately exact and local to the integration test;
	// production retention goes through the bounded PruneAudit operation.
	for _, q := range []string{"DELETE FROM kernel_event", "DELETE FROM audit_session"} {
		if _, err := st.pool.Exec(ctx, q); err != nil {
			t.Fatalf("cleanup %q: %v", q, err)
		}
	}
}

// TestListInventoryMergesObservedIPs confirms `vctl list` sees agent-observed
// addresses without pulling the full runtime status: ListInventory folds
// observed_ips into Addresses. Integration — needs VCTL_TEST_DSN.
func TestListInventoryMergesObservedIPs(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := "inv-host-" + time.Now().Format("150405.000000")
	dc := "inv-dc-" + time.Now().Format("150405.000000")
	// The hostname is unique per run but the address is not, and Upsert matches
	// an existing host by IP and keeps its hostname. Without clearing the address
	// the second run against a persistent database updates the first run's row
	// and this test's hostname never exists.
	freeAddress(t, st, "192.0.2.50")

	if err := st.Upsert(ctx, Server{
		Hostname: host, IP: "192.0.2.50", Port: 22, User: "ubuntu", DC: dc,
		CARole: "sre-core",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// extra_ips are operator-curated via their own path, not sync-derived Upsert.
	if _, err := st.SetExtraIPs(ctx, host, []string{"192.0.2.51"}); err != nil {
		t.Fatalf("SetExtraIPs: %v", err)
	}
	if _, err := st.UpsertServerStatus(ctx, ServerStatus{
		Hostname: host, AgentVersion: "test", ObservedIPs: []string{"192.0.2.52", "192.0.2.50"},
	}); err != nil {
		t.Fatalf("UpsertServerStatus: %v", err)
	}

	rows, err := st.ListInventory(ctx, dc)
	if err != nil {
		t.Fatalf("ListInventory: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	got := rows[0].Addresses
	want := []string{"192.0.2.50", "192.0.2.51", "192.0.2.52"} // primary, extra, observed; dedup drops the repeat
	if len(got) != len(want) {
		t.Fatalf("Addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Addresses[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
}

func TestServerStatusDoesNotCreateInventory(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	host := "status-host-" + time.Now().Format("150405.000000")
	freeAddress(t, st, "192.0.2.10")

	ok, err := st.UpsertServerStatus(ctx, ServerStatus{Hostname: host, AgentVersion: "test"})
	if err != nil {
		t.Fatalf("UpsertServerStatus absent host: %v", err)
	}
	if ok {
		t.Fatal("UpsertServerStatus reported success for absent inventory host")
	}

	if err := st.Upsert(ctx, Server{
		Hostname: host,
		IP:       "192.0.2.10",
		Port:     22,
		User:     "ubuntu",
		DC:       "test",
		CARole:   "sre-core",
	}); err != nil {
		t.Fatalf("Upsert server: %v", err)
	}
	load := 0.25
	ok, err = st.UpsertServerStatus(ctx, ServerStatus{
		Hostname:     host,
		AgentVersion: "test",
		OS:           "linux",
		Load1:        &load,
	})
	if err != nil || !ok {
		t.Fatalf("UpsertServerStatus registered host = (%v,%v), want (true,nil)", ok, err)
	}

	servers, err := st.ListWithStatus(ctx, "test")
	if err != nil {
		t.Fatalf("ListWithStatus: %v", err)
	}
	var found *ServerWithStatus
	for i := range servers {
		if servers[i].Hostname == host {
			found = &servers[i]
			break
		}
	}
	if found == nil || found.Status == nil {
		t.Fatalf("status for %s not found in %+v", host, servers)
	}
	if found.Status.AgentVersion != "test" || found.Status.Load1 == nil || *found.Status.Load1 != load {
		t.Fatalf("status = %+v, want agent version and load", found.Status)
	}
}

// The pool's recycling policy is a trade between two costs that pull in opposite
// directions: recycling too late reuses a dead Vault lease, recycling too early
// burns a Vault issuance and a Postgres role per cycle. Both failure modes are
// silent — one surfaces as an authentication error under load, the other only as
// a role count nobody is watching — so the bounds are asserted rather than left
// to the comments in tunePool.

func TestPoolLifetimeStaysInsideCredentialLease(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://localhost:5432/vctl")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	tunePool(cfg)

	// pgx computes the deadline as now+lifetime+jitter, so jitter is spent from
	// the lease window, not held back from it. A connection reaching this age has
	// a credential Vault has already revoked.
	worst := cfg.MaxConnLifetime + cfg.MaxConnLifetimeJitter
	if worst >= credentialTTL {
		t.Errorf("worst-case connection age %v >= credential TTL %v: connections outlive their lease",
			worst, credentialTTL)
	}
	if margin := credentialTTL - worst; margin < 5*time.Minute {
		t.Errorf("margin under credential TTL is %v, want >= 5m for clock skew and slow reconnects", margin)
	}
}

func TestPoolIdleTimeoutDoesNotRaceDaemonHeartbeat(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://localhost:5432/vctl")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	tunePool(cfg)

	// An idle timeout at or under the heartbeat interval makes the connection
	// collectable exactly when it is next needed. The reconnect that follows is
	// pure waste: a Vault issuance and a new Postgres role to replace a healthy
	// connection. This regressed once at 5m against a 5m interval.
	if cfg.MaxConnIdleTime <= maxDaemonInterval {
		t.Errorf("MaxConnIdleTime %v <= daemon heartbeat %v: the reaper races the next write",
			cfg.MaxConnIdleTime, maxDaemonInterval)
	}
	// Idling past the lifetime cap cannot happen, and pretending otherwise would
	// hide a lifetime that had been shortened below the idle timeout.
	if cfg.MaxConnIdleTime >= cfg.MaxConnLifetime {
		t.Errorf("MaxConnIdleTime %v >= MaxConnLifetime %v: the idle timeout can never fire",
			cfg.MaxConnIdleTime, cfg.MaxConnLifetime)
	}
}

// Caching a credential only pays off if there is a usable window between the
// moment it is issued and the moment it can no longer cover a new connection's
// full life. That window is credentialTTL - MaxConnAge - the holder's margin.
// Pushing the connection lifetime toward the TTL shrinks it, and a window near
// zero silently turns the cache back into issue-per-connection — the behavior
// it was written to replace, with none of the errors that would reveal it.
func TestCredentialReuseWindowIsWorthCaching(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://localhost:5432/vctl")
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	tunePool(cfg)

	if got, max := MaxConnAge(), credentialTTL/2; got > max {
		t.Errorf("MaxConnAge is %v, more than half the %v credential TTL (%v): "+
			"too little of each credential's life is left for reuse", got, credentialTTL, max)
	}
}
