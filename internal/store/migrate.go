package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgerrcodeUndefinedTable is SQLSTATE 42P01 — how Postgres says the ledger has
// never been created.
const pgerrcodeUndefinedTable = "42P01"

//go:embed migrations/*.sql
var migrations embed.FS

// migrateLockKey is the advisory lock every migrator takes before reading the
// ledger. The value is arbitrary but must never change: two processes agree
// only because they pick the same number. It is the ASCII of "vctlmigr", which
// makes it recognisable in pg_locks when something is stuck.
//
// Without this, two instances starting together both find the ledger empty and
// both run the same DDL. Today that survives only because every migration is
// written defensively; the lock is what makes it survive on purpose.
const migrateLockKey int64 = 0x7663746c6d696772

// migrateLockTimeout bounds the wait for that lock. A migrator that blocks
// forever behind a stuck one looks identical to a hung startup, and the whole
// point of failing here is that somebody goes and looks.
const migrateLockTimeout = 60 * time.Second

// schemaMigrationsDDL bootstraps the ledger itself.
//
// It cannot live in migrations/ — the runner has to read the ledger to decide
// what to run, so the table must exist before that decision. Creating it here
// on every run is the one statement that stays unconditional.
const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    checksum   TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// schemaMigrationsGrant lets read-only roles see what the database has, which is
// what makes "which migrations are applied" answerable without the credentials
// that could change them. Guarded the same way the migrations guard their own
// grants: local and test databases have no group roles.
const schemaMigrationsGrant = `DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_ro') THEN
        GRANT SELECT ON schema_migrations TO vctl_ro;
    END IF;
END $$`

// AppliedMigration is one row of the ledger.
type AppliedMigration struct {
	Version   string
	Checksum  string
	AppliedAt time.Time
}

// Migrate runs embedded migrations that have not been applied yet.
func (s *Store) Migrate(ctx context.Context) error {
	return s.MigrateAsOwner(ctx, "")
}

// MigrateAsOwner applies pending migrations, recording each in schema_migrations
// so it is never run twice, and refusing to proceed if an already-applied file
// has changed since.
//
// owner switches to a stable role for the duration, so permanent tables are not
// left owned by a Vault dynamic role that will be revoked in an hour.
//
// # Why a ledger
//
// Before this, every SQL file re-ran on every startup. That worked only because
// each one was written to tolerate it — CREATE TABLE IF NOT EXISTS, ADD COLUMN
// IF NOT EXISTS, DO $$ IF NOT EXISTS $$. That is a convention, not a guarantee,
// and the first plain ALTER TABLE anyone writes breaks the second startup. The
// ledger turns the convention into something the runner enforces.
//
// # Why no baseline
//
// A database that already has the schema gets its migrations replayed once, on
// the first run under this scheme, and recorded as it goes. The tempting
// alternative — declare everything already applied and skip it — assumes the
// database is exactly as new as this binary. It is not necessarily: a cluster
// last touched by an older build is missing whatever came after, and a blanket
// baseline would mark those applied without running them, leaving a schema that
// is silently short a column.
//
// Replaying is safe for exactly the reason the old runner worked at all: these
// files already run on every single startup today. One more pass is the status
// quo, and after it the ledger is authoritative.
//
// # Why no retry
//
// If the connection drops mid-DDL, the client cannot know whether the commit
// landed. Retrying would risk writing on top of a partial apply. This returns
// the error and stops; re-running it deliberately, once somebody has looked, is
// the recovery path.
func (s *Store) MigrateAsOwner(ctx context.Context, owner string) error {
	files, err := embeddedMigrations()
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if owner != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{owner}.Sanitize()); err != nil {
			return fmt.Errorf("set migration owner %s: %w", owner, err)
		}
	}

	// Bound the wait before taking the lock, or a stuck migrator turns this into
	// an indefinite hang with no message.
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL lock_timeout = '%dms'", migrateLockTimeout.Milliseconds())); err != nil {
		return fmt.Errorf("set lock timeout: %w", err)
	}
	// Transaction-scoped: released on commit, on rollback, and on a dropped
	// connection. A session-scoped lock would survive a crashed migrator and
	// block every later one until somebody found it by hand.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrateLockKey); err != nil {
		return fmt.Errorf("acquire migration lock (another migration may be running): %w", err)
	}

	if _, err := tx.Exec(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	if _, err := tx.Exec(ctx, schemaMigrationsGrant); err != nil {
		return fmt.Errorf("grant on schema_migrations: %w", err)
	}

	applied, err := appliedChecksums(ctx, tx)
	if err != nil {
		return err
	}

	for _, f := range files {
		if was, ok := applied[f.name]; ok {
			if was != f.checksum {
				// Editing an applied migration means the database and the file no
				// longer describe the same schema, and nothing here can tell which
				// one is right. Say so rather than guessing.
				return fmt.Errorf(
					"migration %s changed after it was applied (recorded %s, now %s): "+
						"add a new migration instead of editing an applied one",
					f.name, short(was), short(f.checksum))
			}
			continue
		}
		if _, err := tx.Exec(ctx, f.sql); err != nil {
			return fmt.Errorf("migration %s: %w", f.name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`,
			f.name, f.checksum); err != nil {
			return fmt.Errorf("record migration %s: %w", f.name, err)
		}
	}
	return tx.Commit(ctx)
}

// AppliedMigrations returns the ledger, oldest first. It is the answer to "what
// does this database actually have", which before the ledger nothing could say.
func (s *Store) AppliedMigrations(ctx context.Context) ([]AppliedMigration, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT version, checksum, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	return collectRows(rows, func(r pgx.Rows) (AppliedMigration, error) {
		var m AppliedMigration
		err := r.Scan(&m.Version, &m.Checksum, &m.AppliedAt)
		return m, err
	})
}

// PendingMigrations reports the embedded migrations this database has not
// recorded. It reads without locking, so it is safe to call for reporting while
// something else migrates — the answer is a snapshot, not a reservation.
func (s *Store) PendingMigrations(ctx context.Context) ([]string, error) {
	files, err := embeddedMigrations()
	if err != nil {
		return nil, err
	}
	applied, err := s.AppliedMigrations(ctx)
	if err != nil {
		// A missing ledger means nothing has been recorded, so everything is
		// pending — the honest answer on a database this scheme has not touched.
		//
		// Only that one error. Reporting "all pending" for, say, a permission
		// failure would turn a credentials problem into a plausible-looking
		// schema answer, and send the operator looking in the wrong place.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgerrcodeUndefinedTable {
			return names(files), nil
		}
		return nil, err
	}
	have := make(map[string]bool, len(applied))
	for _, a := range applied {
		have[a.Version] = true
	}
	var out []string
	for _, f := range files {
		if !have[f.name] {
			out = append(out, f.name)
		}
	}
	return out, nil
}

type migrationFile struct {
	name     string
	sql      string
	checksum string
}

func names(files []migrationFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.name)
	}
	return out
}

// embeddedMigrations reads the embedded files in sorted order, hashing each.
//
// The checksum is over the file bytes, so reformatting a migration counts as
// changing it. That is deliberate: the runner cannot tell a cosmetic edit from
// a semantic one, and the safe reading of "this file is not what we ran" is to
// stop.
func embeddedMigrations() ([]migrationFile, error) {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	out := make([]migrationFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, migrationFile{
			name:     e.Name(),
			sql:      string(b),
			checksum: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func appliedChecksums(ctx context.Context, tx pgx.Tx) (map[string]string, error) {
	rows, err := tx.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			return nil, err
		}
		out[version] = checksum
	}
	return out, rows.Err()
}

// short trims a checksum for an error message. The full hash proves nothing to
// a reader that the first few characters do not.
func short(sum string) string {
	if len(sum) <= 12 {
		return sum
	}
	return sum[:12]
}
