// Package audit is the access to audit data, scoped to what each caller may do
// with it.
//
// Vault already splits this three ways — vctl-audit-ro reads, vctl-audit-writer
// appends access attempts, vctl-audit-ingest maintains sessions and events —
// and the database enforces it. The code did not: every caller received the
// same 84-method store, so `vctl session`, which needs three read methods and
// holds a read-only credential, was handed the same object that can delete a
// host. Nothing failed, because the credential stops it. But the interface said
// the opposite of what the privilege boundary said, and the only thing keeping
// them aligned was that nobody had written the wrong call yet.
//
// This is not a wrapper per table. What it hides is the workflow around one:
// choosing the role, obtaining the credential, holding the pool open for
// exactly as long as the work takes, and closing it — repeated at eight call
// sites, each with its own defer.
//
// The scopes are separate types rather than one interface with everything on
// it, because that is the boundary itself. A collector holding an Ingestor
// cannot read a session timeline, and the compiler is what says so.
package audit

import (
	"context"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// Reader is what the read-only audit role may do: look at what happened.
type Reader interface {
	AccessLog(ctx context.Context, limit int, hostFilter, userFilter, sourceIPFilter string) ([]store.AccessEntry, error)
	ListSessions(ctx context.Context, hostFilter string, limit int) ([]store.AuditSession, error)
	SessionTimeline(ctx context.Context, certSerial string, limit int) ([]store.AuditSession, map[int64][]store.KernelEvent, error)

	// The retention counts are reads: they say how much there is before
	// anything is asked to remove it, and the removal itself belongs to the
	// pruner, which is a CronJob and not this process.
	AuditFootprint(ctx context.Context) ([]store.TableFootprint, error)
	CountKernelEventsBefore(ctx context.Context, t time.Time) (int64, error)
	CountSessionsBefore(ctx context.Context, t time.Time) (int64, error)
}

// Ingestor is what the ingest role may do: record sessions as they start and
// end, and append the events inside them.
//
// No deletes and no reads of anybody else's session. A host collector's whole
// job is to add to the record, and the narrowest thing that can do that job is
// what it should be handed.
type Ingestor interface {
	RecordSession(ctx context.Context, a store.AuditSession) (int64, error)
	EndSession(ctx context.Context, id int64, endedAt time.Time, summary string) error
	UnendedSessions(ctx context.Context, host string) ([]store.AuditSession, error)
	InsertKernelEvents(ctx context.Context, evs []store.KernelEvent) (int, error)
	InsertKernelEventsAttributed(ctx context.Context, evs []store.KernelEvent) (int, []int, error)
}

// Conn is an open audit connection: everything the two scopes need, plus the
// close this package owns.
//
// The union exists so the opener can be faked. Returning the concrete store
// here would have made this module unusable without a database — the same
// mistake it exists to correct, one layer up.
type Conn interface {
	Reader
	Ingestor
	Close()
}

// Open dials the audit database with the role a scope requires. What it returns
// is closed by this package, never by the caller.
type Open func(ctx context.Context, purpose Purpose) (Conn, error)

// Purpose names which credential a scope needs. The values mirror the Vault
// database roles, and the mapping to them lives with the app that holds the
// Vault session — this package says which one is wanted, not how to get it.
type Purpose int

const (
	Read Purpose = iota
	Ingest
)

// Store is audit access with its credentials and pool lifetime hidden.
type Store struct{ open Open }

// New builds the accessor. The single dependency is how to open a store for a
// purpose, which is the app's job because it holds the Vault session.
func New(open Open) *Store { return &Store{open: open} }

// Reading runs fn against the read-only audit role.
//
// The store is opened when the work starts and closed when it ends, so a
// dynamic credential's lease lives exactly as long as the command that needed
// it. Eight call sites each had their own version of that, and each had its own
// defer to get wrong.
func (s *Store) Reading(ctx context.Context, fn func(Reader) error) error {
	return s.with(ctx, Read, func(c Conn) error { return fn(c) })
}

// Ingesting runs fn against the ingest role.
func (s *Store) Ingesting(ctx context.Context, fn func(Ingestor) error) error {
	return s.with(ctx, Ingest, func(c Conn) error { return fn(c) })
}

func (s *Store) with(ctx context.Context, p Purpose, fn func(Conn) error) error {
	c, err := s.open(ctx, p)
	if err != nil {
		return err
	}
	defer c.Close()
	return fn(c)
}
