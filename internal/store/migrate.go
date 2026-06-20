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

// Migrate 는 embed 된 마이그레이션을 순서대로 실행한다(멱등 — IF NOT EXISTS).
func (s *Store) Migrate(ctx context.Context) error {
	return s.MigrateAsOwner(ctx, "")
}

// MigrateAsOwner 는 트랜잭션 안에서 stable owner role 로 전환한 뒤 마이그레이션을 실행한다.
// Vault 동적 DB role 이 영구 테이블 owner 가 되지 않도록 하기 위한 경로다.
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
