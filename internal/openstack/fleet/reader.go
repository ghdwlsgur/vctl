package fleet

import (
	"context"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// One way to get a reading, and one place that decides where it came from.
//
// The decision used to be spread over the commands that needed it. A listing
// knew which shape to ask for, whether it was allowed to answer from disk, how
// old was too old, whether to fall back to a stale reading when the database
// refused, when to open the database at all, and when to say on stderr that the
// answer was not live. Every one of those is a rule about the fleet, and none of
// them is about printing a table.
//
// It showed. `vctl openstack` and `vctl openstack farm list` served a stored
// reading when the database was unreachable; `vctl openstack vm` did not, and
// failed instead — not by decision but because its copy of the sequence was
// written separately and stopped one branch earlier. Two of the three announced
// the age; the third returned it and left the announcement to its caller.
//
// A Reader answers a ReadRequest with a Reading that says where it came from.
// What is left at the call site is what a command should own: what it asked for,
// and how it prints the answer.
type Reader struct {
	// Cache is where readings are kept between runs. A nil Cache is a working
	// Reader that always reads the database — that is what a machine with no
	// writable state directory gets, and it must be a slower command rather than
	// a broken one.
	Cache *Cache

	// Load reads the fleet from the database.
	//
	// It returns the snapshot rather than the catalog because the Reader stores
	// what it read, and a catalog cannot be stored: From has already folded the
	// rows into the shape a screen wants, and storing that under a shape name
	// would promise rows it no longer has.
	Load func(context.Context) (store.Fleet, error)

	// now exists for tests. Nil means time.Now.
	now func() time.Time
}

// Source is where a reading came from. The distinction is not trivia: it decides
// what the command tells the operator, and whether it says anything at all.
type Source int

const (
	// FromDatabase is a live read. Nothing to announce.
	FromDatabase Source = iota

	// FromStored is the reading on disk, young enough for the purpose. Worth a
	// note, because somebody may act on it.
	FromStored

	// FromFallback is a reading past its fresh window, served because the
	// database did not answer. Worth a warning, because two things are now
	// true at once: the picture is old, and the database is down.
	FromFallback
)

func (s Source) String() string {
	switch s {
	case FromDatabase:
		return "database"
	case FromStored:
		return "cache"
	case FromFallback:
		return "fallback"
	}
	return "unknown"
}

// ReadRequest is what a command wants, in the fleet's own terms.
type ReadRequest struct {
	// Shape is the least a reading must carry. It is a floor, not an exact
	// match: a request for ShapeFarms is answered by a stored ShapeVMs reading
	// when that one is newer.
	Shape Shape

	// Purpose is what the answer is for, which is what sets the fresh window.
	// See Purpose — a purpose that may not read stored readings gets the
	// database or an error, never something old.
	Purpose Purpose

	// Live is the operator asking for the database specifically: --fresh, or
	// --json, where the note saying how old an answer is goes to a stderr the
	// consuming program cannot read.
	Live bool
}

// Reading is an answer and its provenance.
type Reading struct {
	Catalog Catalog
	Source  Source

	// Age is how long ago the reading was captured. Zero for a live read, which
	// is the truth rather than a placeholder: it was captured now.
	Age time.Duration

	// Err is why the database was not used, set only on FromFallback. The
	// operator is being shown an old picture and is owed the reason — "database
	// unreachable" without it leaves them guessing between a network, a
	// credential and a server that is simply down.
	Err error
}

// Stale reports whether this answer is one the operator should be told about.
func (r Reading) Stale() bool { return r.Source != FromDatabase }

func (r *Reader) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Stored answers from disk or not at all. Its Reading carries the same
// provenance as Read, so callers do not have to reconstruct source and age from
// parallel return values.
//
// This is the whole of what a completion may do: a Tab keypress has to answer
// now or it is not completion, and opening a database to do it would make the
// shell hang on a Vault round trip. Separate from Read because "answer from disk
// or say nothing" and "answer from disk or go and look" are different
// operations, and a completion that fell through to the database would be a
// completion that sometimes took ten seconds.
func (r *Reader) Stored(shape Shape, why Purpose) (Reading, bool) {
	if r == nil || r.Cache == nil || !why.MayReadStored() {
		return Reading{}, false
	}
	now := r.clock()
	got, err := r.Cache.LoadAtLeast(shape, now)
	if err != nil {
		return Reading{}, false
	}
	if age := got.Age(now); age <= why.MaxAge() {
		return Reading{Catalog: From(got.Fleet), Source: FromStored, Age: age}, true
	}
	return Reading{}, false
}

// Read answers a request from the stored reading or the database, in that order,
// and falls back to a stale reading when the database will not answer.
//
// The order is the point. Reading the database costs a Vault round trip, a
// dynamic credential and a TLS handshake before the query runs — measured at
// about 98% of a listing's cost, against 1.5% for the query itself — so a stored
// reading that is fresh enough is not an optimisation, it is the difference
// between a listing that returns and one somebody waits out.
//
// The fallback at the end is most of why anything is stored. Without it the
// fresh window was also the offline window, so a listing went from instant to
// failed five minutes after the last successful read — during an outage, which
// is exactly when somebody wants to see what the fleet last looked like.
func (r *Reader) Read(ctx context.Context, req ReadRequest) (Reading, error) {
	if !req.Live {
		if rd, ok := r.Stored(req.Shape, req.Purpose); ok {
			return rd, nil
		}
	}
	snap, err := r.Load(ctx)
	if err == nil {
		// Stored under the shape that was asked for, which is what the shape
		// means: every writer of a shape carried at least that much, so a later
		// reader of it can rely on the rows being there.
		if r.Cache != nil {
			_ = r.Cache.Save(req.Shape, snap)
		}
		return Reading{Catalog: From(snap), Source: FromDatabase}, nil
	}
	if !req.Live {
		if rd, ok := r.Stored(req.Shape, ForFallback); ok {
			rd.Source, rd.Err = FromFallback, err
			return rd, nil
		}
	}
	return Reading{}, err
}
