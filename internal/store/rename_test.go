package store

import (
	"context"
	"testing"
)

// seedRenameFixture registers a host and gives it one row in every table a
// rename has to carry, plus one audit row it must not touch.
func seedRenameFixture(t *testing.T, st *Store, host string) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := st.pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	exec(`DELETE FROM servers WHERE hostname=$1`, host)
	if _, err := st.Insert(ctx, Server{
		Hostname: host, IP: "198.51.100.7", Port: 22, User: "rocky", DC: "test-dc", CARole: "sre-core",
	}); err != nil {
		t.Fatalf("insert %s: %v", host, err)
	}
	exec(`INSERT INTO server_status (hostname, last_seen_at, agent_version)
	      VALUES ($1, now(), 'test') ON CONFLICT (hostname) DO UPDATE SET agent_version='test'`, host)
	exec(`INSERT INTO wg_interfaces (host, iface, public_key) VALUES ($1,'wg0','pk-iface')
	      ON CONFLICT (host, iface) DO NOTHING`, host)
	exec(`INSERT INTO wg_peers (host, iface, peer_pubkey) VALUES ($1,'wg0','pk-peer')
	      ON CONFLICT (host, iface, peer_pubkey) DO NOTHING`, host)
	exec(`INSERT INTO wg_peer_status (host, iface, peer_pubkey) VALUES ($1,'wg0','pk-peer')
	      ON CONFLICT (host, iface, peer_pubkey) DO NOTHING`, host)
	exec(`INSERT INTO access_log (hostname, client_user, vault_user) VALUES ($1,'rocky','tester')`, host)
}

func countWhere(t *testing.T, st *Store, table, column, value string) int {
	t.Helper()
	var n int
	err := st.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+table+` WHERE `+column+`=$1`, value).Scan(&n)
	if err != nil {
		t.Fatalf("count %s.%s: %v", table, column, err)
	}
	return n
}

// A rename has to carry everything that describes the host as it is now. There
// are no foreign keys in this schema, so nothing enforces it: a missed table
// keeps its old key and silently stops joining, and each one fails somewhere
// different — the host reads as no-agent, or its WireGuard interfaces vanish
// from the graph. Integration — needs VCTL_TEST_DSN.
func TestRenameCarriesEveryHostnameKeyedTable(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const old, renamed = "rename-src-01", "rename-dst-01"

	seedRenameFixture(t, st, old)
	t.Cleanup(func() {
		for _, h := range []string{old, renamed} {
			_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM server_status WHERE hostname=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_interfaces WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_peers WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_peer_status WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM access_log WHERE hostname=$1`, h)
		}
	})

	ok, err := st.Rename(ctx, old, renamed)
	if err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if !ok {
		t.Fatal("Rename reported no match for a host it had just been given")
	}

	for _, c := range renameCarried {
		if n := countWhere(t, st, c.table, c.column, old); n != 0 {
			t.Errorf("%s.%s still has %d row(s) under the old name", c.table, c.column, n)
		}
	}
	for _, c := range []struct{ table, column string }{
		{"server_status", "hostname"},
		{"wg_interfaces", "host"},
		{"wg_peers", "host"},
		{"wg_peer_status", "host"},
	} {
		if n := countWhere(t, st, c.table, c.column, renamed); n != 1 {
			t.Errorf("%s.%s has %d row(s) under the new name, want 1", c.table, c.column, n)
		}
	}

	// Audit history keeps the old name. It records what happened on that machine
	// under the name it had at the time; rewriting it would make the history
	// claim something that was never true.
	if n := countWhere(t, st, "access_log", "hostname", old); n != 1 {
		t.Errorf("access_log has %d row(s) under the old name, want the history kept", n)
	}
	if n := countWhere(t, st, "access_log", "hostname", renamed); n != 0 {
		t.Errorf("access_log was rewritten to the new name (%d rows)", n)
	}
}

// Delete removes a host from servers only, so a retired host can leave rows in
// the keyed tables. Renaming onto that name would hit the primary key. The
// leftovers describe a machine the inventory no longer has, so they go.
// Integration — needs VCTL_TEST_DSN.
func TestRenameClearsRowsLeftByARetiredHost(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const old, renamed = "rename-src-02", "rename-dst-02"

	seedRenameFixture(t, st, old)
	// A host that used to hold the target name, then was deleted from servers.
	seedRenameFixture(t, st, renamed)
	if _, err := st.pool.Exec(ctx, `UPDATE server_status SET agent_version='ghost' WHERE hostname=$1`, renamed); err != nil {
		t.Fatalf("mark ghost: %v", err)
	}
	if _, err := st.Delete(ctx, renamed); err != nil {
		t.Fatalf("delete: %v", err)
	}
	t.Cleanup(func() {
		for _, h := range []string{old, renamed} {
			_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM server_status WHERE hostname=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_interfaces WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_peers WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_peer_status WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM access_log WHERE hostname=$1`, h)
		}
	})

	if _, err := st.Rename(ctx, old, renamed); err != nil {
		t.Fatalf("Rename over a retired host's leftovers: %v", err)
	}

	var version string
	err := st.pool.QueryRow(ctx,
		`SELECT coalesce(agent_version,'') FROM server_status WHERE hostname=$1`, renamed).Scan(&version)
	if err != nil {
		t.Fatalf("read status after rename: %v", err)
	}
	if version == "ghost" {
		t.Error("the renamed host inherited the retired host's heartbeat")
	}
	if n := countWhere(t, st, "server_status", "hostname", renamed); n != 1 {
		t.Errorf("server_status has %d rows for the new name, want exactly 1", n)
	}
}

// Where the hostname is an ordinary attribute rather than a key, a row naming
// the new host belongs to something else. Clearing it — which is right for the
// keyed tables — would destroy an unrelated record here.
// Integration — needs VCTL_TEST_DSN.
func TestRenameDoesNotDeleteRowsThatMerelyMentionTheNewName(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const old, renamed = "rename-src-03", "rename-dst-03"

	seedRenameFixture(t, st, old)
	// An annotation for a different endpoint that happens to name the new host as
	// its physical parent, and an IP ledger entry pointing at it.
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO wg_endpoint_annotations (public_key, label, parent_hostname)
		 VALUES ('pk-bystander','vm-on-the-target',$1)
		 ON CONFLICT (public_key) DO UPDATE SET parent_hostname=EXCLUDED.parent_hostname`, renamed); err != nil {
		t.Fatalf("seed annotation: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`INSERT INTO ip_allocations (ip, kind, hostname) VALUES ('198.51.100.77','server',$1)
		 ON CONFLICT (ip) DO UPDATE SET hostname=EXCLUDED.hostname`, renamed); err != nil {
		t.Fatalf("seed allocation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM wg_endpoint_annotations WHERE public_key='pk-bystander'`)
		_, _ = st.pool.Exec(ctx, `DELETE FROM ip_allocations WHERE ip='198.51.100.77'`)
		for _, h := range []string{old, renamed} {
			_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM server_status WHERE hostname=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_interfaces WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_peers WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_peer_status WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM access_log WHERE hostname=$1`, h)
		}
	})

	if _, err := st.Rename(ctx, old, renamed); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	if n := countWhere(t, st, "wg_endpoint_annotations", "public_key", "pk-bystander"); n != 1 {
		t.Error("an unrelated endpoint annotation was deleted because it named the new host")
	}
	var ip int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM ip_allocations WHERE ip='198.51.100.77'`).Scan(&ip); err != nil {
		t.Fatalf("count allocations: %v", err)
	}
	if ip != 1 {
		t.Error("an unrelated IP allocation was deleted because it named the new host")
	}
}

// A rename to a name already in use must fail before anything moves, or the
// unique index rejects the servers update and the carried tables never run.
// Integration — needs VCTL_TEST_DSN.
func TestRenameOntoALiveHostLeavesBothIntact(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const old, taken = "rename-src-04", "rename-taken-04"

	seedRenameFixture(t, st, old)
	if _, err := st.Insert(ctx, Server{
		Hostname: taken, IP: "198.51.100.8", Port: 22, User: "rocky", DC: "test-dc", CARole: "sre-core",
	}); err != nil {
		t.Fatalf("insert %s: %v", taken, err)
	}
	t.Cleanup(func() {
		for _, h := range []string{old, taken} {
			_, _ = st.pool.Exec(ctx, `DELETE FROM servers WHERE hostname=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM server_status WHERE hostname=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_interfaces WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_peers WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM wg_peer_status WHERE host=$1`, h)
			_, _ = st.pool.Exec(ctx, `DELETE FROM access_log WHERE hostname=$1`, h)
		}
	})

	if _, err := st.Rename(ctx, old, taken); err == nil {
		t.Fatal("Rename onto a name already in the inventory succeeded")
	}
	// The transaction rolled back, so the source host is still there and still
	// has its heartbeat.
	if n := countWhere(t, st, "servers", "hostname", old); n != 1 {
		t.Errorf("the source host is gone after a failed rename (%d rows)", n)
	}
	if n := countWhere(t, st, "server_status", "hostname", old); n != 1 {
		t.Errorf("the source host's heartbeat moved despite the rename failing (%d rows)", n)
	}
}

// Renaming a host nothing points at must report no match rather than quietly
// moving another host's rows onto the target name.
// Integration — needs VCTL_TEST_DSN.
func TestRenameReportsNoMatchForAnUnknownHost(t *testing.T) {
	st := testStore(t)
	ok, err := st.Rename(context.Background(), "rename-does-not-exist", "rename-whatever")
	if err != nil {
		t.Fatalf("Rename of a missing host errored: %v", err)
	}
	if ok {
		t.Error("Rename reported a match for a host that is not in the inventory")
	}
}
