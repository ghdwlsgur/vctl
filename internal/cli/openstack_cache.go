package cli

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// Reaching the stored fleet reading from a command.
//
// These lived in openstack_farm.go, which is the `farm` command's file. It ended
// up the home of the cache policy because loadCatalog was there and everything
// else accreted around it, so the question "may this command answer from disk"
// was answered in a file about naming deployments — next to the two commands
// that are not allowed to ask it.
//
// What may be answered from disk is a rule about the fleet, not about this
// package, and it lives in fleet.Purpose. What is left here is the wiring: an
// *app.App to reach the cache through, a cobra command to read the flags off,
// and the one function that decides between disk and database for a listing.
//
// The four below are the only way into the stored reading from a command, and
// TestNothingThatConnectsOrChangesReadsTheStoredReading holds the files on the
// other side of the line away from them. A guard rather than a convention,
// because the mistake it prevents — a listing helper reused on a connecting path
// because it was there — is one nobody would notice making.

// forgetReadings drops the stored picture after something changed it.
//
// at comes from the database when a store is at hand — the same clock every
// reading's ReadAt uses, so Cache.Clear's ordering marker compares like with
// like. Best-effort: a caller that cannot ask falls back to the local clock
// inside Clear.
// dbClock is the one thing forgetReadings needs from a store: the database's
// idea of now, for the cleared-at marker.
type dbClock interface {
	Now(ctx context.Context) (time.Time, error)
}

func forgetReadings(ctx context.Context, a *app.App, st dbClock) {
	if a == nil {
		return
	}
	c := a.FleetCache()
	if c == nil {
		return
	}
	var at time.Time
	if st != nil {
		if t, err := st.Now(ctx); err == nil {
			at = t
		}
	}
	_ = c.Clear(at)
}

// keepReading stores what was just read, for the next screen.
//
// Only readings that are supersets of their shape are stored. A shape has to
// mean one thing: a caller loading ShapeFarms gets counts and reconcile times
// because every writer of that shape had them, and a lesser reading being
// written under it would turn "no VMs" from a fact into an artefact.
//
// Best effort and silent: a cache that cannot be written is a slower next
// command, not a failed this one, and a warning on every run of a machine with
// a full disk would be noise about something the command did successfully.
func keepReading(a *app.App, shape fleet.Shape, snap store.Fleet) {
	if a == nil {
		return
	}
	if c := a.FleetCache(); c != nil {
		_ = c.Save(shape, snap)
	}
}

// fleetReader is how a listing gets a reading: the stored one when it is fresh
// enough, the database otherwise, and a stale one when the database will not
// answer at all.
//
// The policy is fleet.Reader's — which shape, which window, whether to fall
// back. What is supplied here is the wiring that only this package has: the
// app's cache, and a store that is opened on first use rather than up front, so
// a run answered from disk never pays for a connection it did not need.
func fleetReader(a *app.App, lazy *openLater, load func(context.Context, *store.Store) (store.Fleet, error)) *fleet.Reader {
	r := &fleet.Reader{}
	if a != nil {
		r.Cache = a.FleetCache()
	}
	r.Load = func(ctx context.Context) (store.Fleet, error) {
		var snap store.Fleet
		err := lazy.use(ctx, func(s *store.Store) error {
			got, err := load(ctx, s)
			snap = got
			return err
		})
		return snap, err
	}
	return r
}

// storedReader answers from disk and never opens anything.
//
// For shell completion, which has to answer on a keypress: a Reader with no Load
// cannot fall through to a database, so a completion cannot accidentally acquire
// one and make the shell hang on a Vault round trip.
func storedReader(a *app.App) *fleet.Reader {
	r := &fleet.Reader{}
	if a != nil {
		r.Cache = a.FleetCache()
	}
	return r
}

// announce says where an answer came from, when it did not come from the
// database.
//
// On stderr, so a piped listing still pipes the listing. A listing that quietly
// answers from disk is one somebody will eventually act on without knowing how
// old it was — and the fallback case says why the database was skipped, because
// an operator being shown an old picture is owed the reason.
func announce(r fleet.Reading) {
	switch r.Source {
	case fleet.FromStored:
		ui.Infof(os.Stderr, "cached · read %s ago · --fresh to re-read", strutil.CompactDuration(r.Age))
	case fleet.FromFallback:
		ui.Warnf(os.Stderr, "database unreachable (%v) — showing the reading from %s ago",
			r.Err, strutil.CompactDuration(r.Age))
	}
}

// listingReading is the whole of what a printed listing does to get its data.
//
// One function rather than the same four lines at each listing, because the
// listings drifted apart when it was four lines: `openstack` and `farm list`
// served a stored reading when the database was unreachable and `vm` failed
// instead, not by decision but because its copy stopped one branch earlier.
func listingReading(ctx context.Context, a *app.App, lazy *openLater, shape fleet.Shape, live bool,
	load func(context.Context, *store.Store) (store.Fleet, error),
) (fleet.Reading, error) {
	rd, err := fleetReader(a, lazy, load).Read(ctx, fleet.ReadRequest{
		Shape: shape, Purpose: fleet.ForListing, Live: live,
	})
	if err != nil {
		return fleet.Reading{}, err
	}
	announce(rd)
	return rd, nil
}

// wantsFresh reports whether the operator asked for the database specifically.
//
// Read off the command rather than passed down, because --fresh is one
// persistent flag on `openstack` shared by every listing under it: the answer
// to "is what I am looking at current" should not depend on which of them they
// happened to type.
func wantsFresh(cmd *cobra.Command) bool {
	v, err := cmd.Flags().GetBool("fresh")
	return err == nil && v
}

// mustBeLive reports whether this run may not be answered from disk.
//
// Two things say so. --fresh is somebody asking. --json is the other one, and
// it is not a preference: the note saying how old an answer is goes to stderr
// for a person to read, and a program parsing stdout has no way to see it — so
// it is never handed a reading it cannot check the age of.
//
// One function rather than the same two-term condition written out at each
// listing, because a listing that forgot the second term would keep working and
// quietly feed a stored reading to whatever consumes its JSON.
func mustBeLive(cmd *cobra.Command, asJSON bool) bool {
	return asJSON || wantsFresh(cmd)
}
