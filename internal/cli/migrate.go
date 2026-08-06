package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// migrateCmd applies pending schema migrations, and is deliberately its own
// command rather than a flag on sync.
//
// As `vctl sync --migrate` the schema change was a side effect of an inventory
// refresh: two operations with different blast radii, different credentials and
// different failure meanings behind one invocation. A sync that fails is a
// retry; a migration that fails half-way is somebody looking at the database.
// Separating them also gives the deploy something to run on its own — a Job
// that migrates and exits, before any binary that expects the new schema
// starts.
//
// --status is the read-only half, and it opens the store with read credentials
// on purpose: "what does this database have" should be answerable without
// holding the rights to change it.
func migrateCmd(env CommandEnv) *cobra.Command {
	var status bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending database schema migrations",
		Long: `migrate applies the schema migrations this binary carries that the
database has not recorded yet.

Migrations are tracked in schema_migrations by name and checksum, so an applied
file is never run twice, and a file that changed after it was applied stops the
run instead of guessing which version is right. Concurrent migrators serialise
on a Postgres advisory lock.

There is no automatic retry. If a migration fails, the transaction rolls back
and the error is reported; re-run it deliberately once you have looked.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.newApp()
			if err != nil {
				return err
			}
			if status {
				return migrationStatus(ctx, a)
			}
			return applyMigrations(ctx, a)
		},
	}
	cmd.Flags().BoolVar(&status, "status", false, "show what is applied and what is pending, and change nothing")
	// Deliberately not app-gated. Vault is the boundary for this one: migrating
	// needs `database/creds/vctl-migrator`, which only vctl-admin and the
	// migration Job's policy can read. Nobody reaches the schema without it, and
	// nobody who has it is stopped by a grant table.
	//
	// The app layer also cannot answer here. Its grants live in Postgres, in
	// tables the migrations create — so on a fresh database the gate would need
	// the very schema it is guarding. And a Job authenticating with kubernetes
	// auth has no per-person identity to look up: the grant table is a table of
	// people, and putting a workload in it to satisfy a check is the wrong shape.
	//
	// Authentication still happens — OpenStore calls EnsureLogin before it asks
	// Vault for credentials.
	return cmd
}

// applyMigrations runs the pending set and names what it ran. Reporting the
// count alone would leave "2 applied" with no way to tell which two, which is
// the first thing anyone asks when the next command misbehaves.
func applyMigrations(ctx context.Context, a *app.App) error {
	st, err := a.OpenStore(ctx, app.PurposeMigrate)
	if err != nil {
		return err
	}
	defer st.Close()

	ran, err := st.MigrateAsOwner(ctx, a.Cfg.DBMigrationOwner)
	if err != nil {
		return err
	}
	if len(ran) == 0 {
		ui.Infof(os.Stderr, "schema is up to date")
		return nil
	}
	ui.Successf(os.Stderr, "applied %d migration(s)", len(ran))
	for _, name := range ran {
		fmt.Fprintf(os.Stderr, "  %s\n", name)
	}
	return nil
}

// migrationStatus prints the ledger and whatever this binary carries that is
// not in it.
func migrationStatus(ctx context.Context, a *app.App) error {
	st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
	if err != nil {
		return err
	}
	defer st.Close()

	applied, err := st.AppliedMigrations(ctx)
	if err != nil {
		return err
	}
	pending, err := st.PendingMigrations(ctx)
	if err != nil {
		return err
	}

	renderMigrationStatus(os.Stdout, applied, pending)
	return nil
}

// renderMigrationStatus writes the ledger and whatever is not in it.
//
// Taking a writer rather than printing to stdout is what makes the layout
// checkable without a Vault round trip and a live database — the same reason
// renderInventory does it.
func renderMigrationStatus(w io.Writer, applied []store.AppliedMigration, pending []string) {
	ui.Section(w, "Schema migrations")

	if len(applied) == 0 {
		ui.Infof(w, "nothing recorded — no build that keeps a ledger has migrated this database")
	} else {
		rows := make([][]string, 0, len(applied))
		for _, m := range applied {
			rows = append(rows, []string{m.Version, m.AppliedAt.Local().Format(ui.TimeLayout)})
		}
		widths := ui.ColumnWidths(rows)
		for _, r := range rows {
			fmt.Fprintf(w, "  %s  %s\n", ui.PadRight(r[0], widths[0]), ui.Muted(r[1]))
		}
	}

	if len(pending) == 0 {
		fmt.Fprintln(w)
		ui.Successf(w, "up to date · %d applied", len(applied))
		return
	}
	fmt.Fprintln(w)
	ui.Warnf(w, "%d pending", len(pending))
	for _, name := range pending {
		fmt.Fprintf(w, "  %s\n", ui.Warn(name))
	}
	// The status command deliberately changes nothing, so it has to say what
	// does. Reporting a pending count with no next step is a dead end.
	ui.Infof(w, "run: vctl migrate")
}
