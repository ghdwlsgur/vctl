package store

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every embedded file has to be readable and hashable, and the order the runner
// applies them in is the filename order. This needs no database.
func TestEmbeddedMigrationsAreSortedAndHashed(t *testing.T) {
	files, err := embeddedMigrations()
	if err != nil {
		t.Fatalf("embeddedMigrations: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no migrations were embedded")
	}
	for i, f := range files {
		if f.sql == "" {
			t.Errorf("%s is empty", f.name)
		}
		if len(f.checksum) != 64 {
			t.Errorf("%s checksum %q is not a sha256 hex digest", f.name, f.checksum)
		}
		if i > 0 && files[i-1].name >= f.name {
			t.Errorf("out of order: %s came before %s", files[i-1].name, f.name)
		}
	}
	// Hashing has to be stable across calls, or every run would look like an
	// edited migration and refuse to start.
	again, err := embeddedMigrations()
	if err != nil {
		t.Fatalf("embeddedMigrations: %v", err)
	}
	for i := range files {
		if files[i].checksum != again[i].checksum {
			t.Errorf("%s hashed differently on a second read", files[i].name)
		}
	}
}

// The point of the ledger: a file that has been applied is not run again.
// Integration — needs VCTL_TEST_DSN.
func TestMigrateRecordsEachFileAndSkipsItNextTime(t *testing.T) {
	st := testStore(t) // testStore already migrated once
	ctx := context.Background()

	applied, err := st.AppliedMigrations(ctx)
	if err != nil {
		t.Fatalf("AppliedMigrations: %v", err)
	}
	// Every embedded file has to be recorded with a matching checksum. The
	// converse is deliberately not asserted: the ledger may hold rows this
	// binary has never heard of, which is what a rollback looks like — a newer
	// build migrated the database and then someone deployed an older one. See
	// TestMigrateToleratesLedgerRowsFromANewerBinary.
	recorded := make(map[string]string, len(applied))
	for _, a := range applied {
		recorded[a.Version] = a.Checksum
	}
	files, _ := embeddedMigrations()
	for _, f := range files {
		sum, ok := recorded[f.name]
		if !ok {
			t.Errorf("%s was applied but not recorded", f.name)
			continue
		}
		if sum != f.checksum {
			t.Errorf("%s recorded checksum does not match the file", f.name)
		}
	}

	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		t.Fatalf("PendingMigrations: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %v, want none after a migrate", pending)
	}

	// applied_at is the evidence. If the runner re-executed a recorded file it
	// would have to rewrite the row, so an unchanged timestamp is proof it was
	// skipped rather than merely surviving a re-run.
	before := map[string]time.Time{}
	for _, a := range applied {
		before[a.Version] = a.AppliedAt
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	after, err := st.AppliedMigrations(ctx)
	if err != nil {
		t.Fatalf("AppliedMigrations: %v", err)
	}
	for _, a := range after {
		if !a.AppliedAt.Equal(before[a.Version]) {
			t.Errorf("%s was applied again on the second run", a.Version)
		}
	}
}

// The runner reports what it ran, because only the transaction that held the
// lock knows. Asking the ledger afterwards answers for whoever migrated last,
// which on a concurrent deploy is a different process.
// Integration — needs VCTL_TEST_DSN.
func TestMigrateReportsTheFilesItApplied(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	files, _ := embeddedMigrations()
	victim := files[len(files)-1]

	// Up to date: nothing to report.
	ran, err := st.MigrateAsOwner(ctx, "")
	if err != nil {
		t.Fatalf("MigrateAsOwner: %v", err)
	}
	if len(ran) != 0 {
		t.Errorf("an up-to-date database reported %v as applied", ran)
	}

	if _, err := st.pool.Exec(ctx,
		`DELETE FROM schema_migrations WHERE version=$1`, victim.name); err != nil {
		t.Fatalf("clear ledger row: %v", err)
	}
	ran, err = st.MigrateAsOwner(ctx, "")
	if err != nil {
		t.Fatalf("MigrateAsOwner: %v", err)
	}
	if len(ran) != 1 || ran[0] != victim.name {
		t.Errorf("applied = %v, want just %s", ran, victim.name)
	}
}

// A rollback leaves the ledger ahead of the binary: a newer build migrated the
// database, then an older one was deployed. It finds a row for a file it does
// not have.
//
// That has to be tolerated. The extra row describes work already done, there is
// nothing for this binary to apply, and refusing to start would make a rollback
// impossible at exactly the moment somebody needs one. (It says nothing about
// whether the older code can *use* the newer schema — that is the deploy's
// problem, not the runner's.)
// Integration — needs VCTL_TEST_DSN.
func TestMigrateToleratesLedgerRowsFromANewerBinary(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const ghost = "999_from_the_future.sql"

	if _, err := st.pool.Exec(ctx,
		`INSERT INTO schema_migrations (version, checksum) VALUES ($1,'deadbeef')
		 ON CONFLICT (version) DO NOTHING`, ghost); err != nil {
		t.Fatalf("seed future migration: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version=$1`, ghost)
	})

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate refused to run against a ledger holding an unknown file: %v", err)
	}
	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		t.Fatalf("PendingMigrations: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %v, want none — an unknown ledger row is not work to do", pending)
	}
}

// A file that has been applied and then edited means the database and the
// repository no longer describe the same schema. Nothing here can tell which is
// right, so it stops instead of guessing.
// Integration — needs VCTL_TEST_DSN.
func TestMigrateRefusesAnAlreadyAppliedFileThatChanged(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	files, _ := embeddedMigrations()
	victim := files[0].name

	var original string
	if err := st.pool.QueryRow(ctx,
		`SELECT checksum FROM schema_migrations WHERE version=$1`, victim).Scan(&original); err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if _, err := st.pool.Exec(ctx,
		`UPDATE schema_migrations SET checksum='0000deadbeef0000' WHERE version=$1`, victim); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.pool.Exec(ctx,
			`UPDATE schema_migrations SET checksum=$2 WHERE version=$1`, victim, original)
	})

	err := st.Migrate(ctx)
	if err == nil {
		t.Fatal("Migrate accepted a migration whose checksum no longer matches")
	}
	if !strings.Contains(err.Error(), victim) {
		t.Errorf("error %q does not name the file", err)
	}
	// The message has to say what to do, not just that something is wrong.
	if !strings.Contains(err.Error(), "add a new migration") {
		t.Errorf("error %q does not say how to resolve it", err)
	}
}

// A row missing from the ledger is re-applied and re-recorded. This is the path
// a database takes the first time it meets this runner: the schema is already
// there, nothing is recorded, and every file runs once more before the ledger
// becomes authoritative. It works because these files are idempotent — which is
// the same property the old runner depended on for every startup.
// Integration — needs VCTL_TEST_DSN.
func TestMigrateReplaysAFileMissingFromTheLedger(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	files, _ := embeddedMigrations()
	victim := files[len(files)-1] // the newest, so a replay exercises real DDL

	if _, err := st.pool.Exec(ctx,
		`DELETE FROM schema_migrations WHERE version=$1`, victim.name); err != nil {
		t.Fatalf("clear ledger row: %v", err)
	}

	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		t.Fatalf("PendingMigrations: %v", err)
	}
	if len(pending) != 1 || pending[0] != victim.name {
		t.Errorf("pending = %v, want just %s", pending, victim.name)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("replaying %s failed — the migration is not idempotent: %v", victim.name, err)
	}

	var checksum string
	if err := st.pool.QueryRow(ctx,
		`SELECT checksum FROM schema_migrations WHERE version=$1`, victim.name).Scan(&checksum); err != nil {
		t.Fatalf("the replayed migration was not recorded: %v", err)
	}
	if checksum != victim.checksum {
		t.Errorf("recorded checksum %q does not match the file", checksum)
	}
}

// Two migrators starting together is the HA case, and the advisory lock is what
// serialises them.
//
// Racing N goroutines does not test this: the DDL takes ACCESS EXCLUSIVE locks
// of its own, so the migrators serialise on the tables whether or not the
// advisory lock exists, and the test passes either way. (Checked by deleting
// the lock and re-running — a racing version stayed green.)
//
// So hold the lock explicitly and show that a migrator waits for it. Under a
// deadline shorter than the wait, Migrate has to fail; with the lock free, the
// same call under the same deadline has to succeed. The pair is what makes the
// blocking attributable to the lock rather than to a slow database.
// Integration — needs VCTL_TEST_DSN.
func TestMigrateWaitsForTheAdvisoryLock(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// A migrator is only made to do work if something is pending.
	files, _ := embeddedMigrations()
	victim := files[len(files)-1]
	if _, err := st.pool.Exec(ctx,
		`DELETE FROM schema_migrations WHERE version=$1`, victim.name); err != nil {
		t.Fatalf("clear ledger row: %v", err)
	}
	t.Cleanup(func() { _ = st.Migrate(context.Background()) })

	holder, err := st.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder: %v", err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrateLockKey); err != nil {
		t.Fatalf("hold the lock: %v", err)
	}

	blocked, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := st.MigrateAsOwner(blocked, ""); err == nil {
		_ = holder.Rollback(ctx)
		t.Fatal("Migrate proceeded while another transaction held the migration lock")
	}
	waited := time.Since(start)
	if waited < time.Second {
		t.Errorf("Migrate gave up after %v — it does not look like it waited on the lock", waited)
	}

	// Release, and the identical call now goes through. Without this half, the
	// failure above could be any error at all.
	if err := holder.Rollback(ctx); err != nil {
		t.Fatalf("release the lock: %v", err)
	}
	free, cancel2 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel2()
	if _, err := st.MigrateAsOwner(free, ""); err != nil {
		t.Fatalf("Migrate failed once the lock was free: %v", err)
	}
	var n int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=$1`, victim.name).Scan(&n); err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	if n != 1 {
		t.Errorf("ledger has %d rows for %s, want 1", n, victim.name)
	}
}

// Migrators that do start together must all finish clean, whichever one does
// the work. This does not prove the lock holds — see the test above for that —
// but it does catch the runner double-inserting or erroring on a no-op pass.
// Integration — needs VCTL_TEST_DSN.
func TestConcurrentMigratorsAllSucceed(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	files, _ := embeddedMigrations()
	victim := files[len(files)-1]

	if _, err := st.pool.Exec(ctx,
		`DELETE FROM schema_migrations WHERE version=$1`, victim.name); err != nil {
		t.Fatalf("clear ledger row: %v", err)
	}

	const racers = 4
	errs := make([]error, racers)
	var wg sync.WaitGroup
	var start sync.WaitGroup
	start.Add(1)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start.Wait() // release them together
			errs[i] = st.Migrate(ctx)
		}()
	}
	start.Done()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("migrator %d failed: %v", i, err)
		}
	}
	var n int
	if err := st.pool.QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version=$1`, victim.name).Scan(&n); err != nil {
		t.Fatalf("count ledger rows: %v", err)
	}
	if n != 1 {
		t.Errorf("ledger has %d rows for %s, want 1", n, victim.name)
	}
}
