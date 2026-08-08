package cli

import (
	"context"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/openstack/fleet"
	"github.com/ghdwlsgur/vctl/internal/store"
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
// A rename, a state change or a reconcile makes what is on disk wrong in the
// one way a cache must never be: it shows somebody what they just changed away
// from. Dropping is deliberate rather than rewriting — the command that changed
// one field has not read the rest, and writing a partly-known picture back is
// how a cache starts inventing.
func forgetReadings(a *app.App) {
	if a == nil {
		return
	}
	if c := a.FleetCache(); c != nil {
		_ = c.Clear()
	}
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

// storedCatalog serves the last reading when it is young enough for what is
// being asked.
//
// The window belongs to the caller's purpose, not to the cache — see
// fleet.Purpose for which purpose gets which, and why. Callers used to pass a
// duration, which meant a call site said how long it would accept rather than
// what it was for, and the two were only connected by a comment.
func storedCatalog(a *app.App, shape fleet.Shape, why fleet.Purpose) (fleet.Catalog, time.Duration, bool) {
	if a == nil || !why.MayReadStored() {
		return fleet.Catalog{}, 0, false
	}
	now := time.Now()
	got, err := a.FleetCache().LoadAtLeast(shape, now)
	if err != nil {
		return fleet.Catalog{}, 0, false
	}
	if age := got.Age(now); age <= why.MaxAge() {
		return fleet.From(got.Fleet), age, true
	}
	return fleet.Catalog{}, 0, false
}

// listingCatalog is what a printed listing reads: the stored reading when it is
// fresh, the database otherwise.
//
// The age is said out loud on stderr. A listing that quietly answers from disk
// is a listing somebody will eventually act on without knowing how old it was —
// and stderr rather than stdout, so a piped listing still pipes the listing.
//
// live forces the database. Two things set it: --fresh, and --json — a program
// reading the output cannot see the note that says how old the answer is, so it
// is given the real thing rather than a claim it has no way to check.
func listingCatalog(ctx context.Context, a *app.App, st *openLater, live bool,
	read func(context.Context, *app.App, *store.Store) (fleet.Catalog, error),
) (fleet.Catalog, error) {
	if !live {
		if cat, age, ok := storedCatalog(a, fleet.ShapeFarms, fleet.ForListing); ok {
			ui.Infof(os.Stderr, "cached · read %s ago · --fresh to re-read", ui.CompactDuration(age))
			return cat, nil
		}
	}
	var out fleet.Catalog
	err := st.use(ctx, func(s *store.Store) error {
		cat, err := read(ctx, a, s)
		out = cat
		return err
	})
	if err == nil {
		return out, nil
	}
	// The database did not answer. A reading past the fresh window is exactly
	// what to serve now — see fleet.ForFallback.
	if !live {
		if cat, age, ok := storedCatalog(a, fleet.ShapeFarms, fleet.ForFallback); ok {
			ui.Warnf(os.Stderr, "database unreachable (%v) — showing the reading from %s ago",
				err, ui.CompactDuration(age))
			return cat, nil
		}
	}
	return out, err
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
