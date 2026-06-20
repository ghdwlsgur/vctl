package store

import (
	"context"
	"embed"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Migrate runs embedded migrations in sorted order.
func (s *Store) Migrate(ctx context.Context) error {
	return s.MigrateAsOwner(ctx, "")
}

// MigrateAsOwner switches to a stable owner role inside a transaction.
// This prevents Vault dynamic DB roles from owning permanent tables.
func (s *Store) MigrateAsOwner(ctx context.Context, owner string) error {
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

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

	for _, name := range names {
		b, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(b)); err != nil {
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return tx.Commit(ctx)
}
