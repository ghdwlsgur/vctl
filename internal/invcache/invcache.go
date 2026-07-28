// Package invcache keeps a local, read-only copy of the central inventory so
// `vctl ssh` and `vctl list` survive a Postgres outage.
//
// Why this exists: the inventory database is a single Postgres instance behind a
// RWO volume (see vctl-postgres), and it has gone down in production — an ENOSPC
// CrashLoop took vctl-ro to 500s and with it every host lookup. Vault, which
// issues the SSH certificate, stayed up the whole time. So the failure mode worth
// designing for is "Postgres unreachable, Vault fine", and all that is missing in
// that window is host topology: slow-changing, operator-managed data that a
// laptop can hold.
//
// Shape of the solution: writes are untouched and still go only to Postgres.
// Reads go through Reader. Online, a Store satisfies it directly and a snapshot
// is refreshed on the side; offline, the snapshot is replayed through Memory,
// which reimplements the resolve/list semantics in Go. The two paths share
// Reader, so the offline query behaviour is the online behaviour.
//
// What is deliberately NOT cached: Vault token policies (the authoritative
// security boundary — caching them would move the boundary onto the laptop) and
// the audit tables (append-heavy, filtered, and pointless offline). Command
// grants are cached but only under a TTL; see Snapshot.Grants.
package invcache

import (
	"context"
	"errors"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// ErrNotFound is returned by Reader.Get when no host carries the hostname. The
// Postgres path surfaces pgx.ErrNoRows for the same condition; callers treat any
// non-nil error from Get as "unresolved", so the two do not have to be equal.
var ErrNotFound = errors.New("host not found in inventory")

// ErrNoSnapshot means nothing usable has been cached yet — a first run, or a
// cleared cache. Callers report the original Postgres failure instead of this,
// since "the database is down" is the actionable half.
var ErrNoSnapshot = errors.New("no local inventory snapshot")

// Reader is the inventory read surface shared by the live database and the local
// snapshot. *store.Store satisfies it as-is; Memory satisfies it from a snapshot.
//
// It covers exactly what host resolution and listing need. Audit, RBAC
// administration, WireGuard, and IP allocation stay on *store.Store: they either
// write, or read data that has no meaning offline.
type Reader interface {
	Get(ctx context.Context, hostname string) (*store.Server, error)
	Resolve(ctx context.Context, query string) (*store.Server, []store.Server, error)
	List(ctx context.Context, dc string) ([]store.Server, error)
	ListInventory(ctx context.Context, dc string) ([]store.InventoryRow, error)
	ListWithStatus(ctx context.Context, dc string) ([]store.ServerWithStatus, error)
}

// Compile-time proof that the live store still satisfies the read surface. If a
// store method signature drifts, this breaks here rather than at the call site.
var _ Reader = (*store.Store)(nil)

// Mode reports where a Reader's answers came from, so commands can label stale
// data instead of presenting it as live.
type Mode int

const (
	// ModeLive means answers come from Postgres.
	ModeLive Mode = iota
	// ModeCached means Postgres was unreachable and answers come from the
	// on-disk snapshot.
	ModeCached
)

func (m Mode) String() string {
	if m == ModeCached {
		return "cached"
	}
	return "live"
}
