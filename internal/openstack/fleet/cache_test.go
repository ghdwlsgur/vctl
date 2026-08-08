package fleet

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func snapshotAt(at time.Time) store.Fleet {
	s := testSnapshot()
	s.ReadAt = at
	return s
}

// A stored reading comes back as what was stored.
func TestAReadingRoundTrips(t *testing.T) {
	c := NewCache(t.TempDir())
	at := time.Now().Add(-time.Minute)
	if err := c.Save(ShapeFarms, snapshotAt(at)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := c.Load(ShapeFarms, time.Now())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !got.CapturedAt.Equal(at) {
		t.Errorf("captured at %v, want %v", got.CapturedAt, at)
	}
	if len(got.Fleet.Deployments) != 3 || len(got.Fleet.Hosts) != 6 {
		t.Errorf("rows lost: %d deployments, %d hosts", len(got.Fleet.Deployments), len(got.Fleet.Hosts))
	}
	// And it still builds the same picture.
	if len(From(got.Fleet).Farms()) != len(From(snapshotAt(at)).Farms()) {
		t.Error("a reading through the cache produces a different catalog")
	}
}

// Age is measured from the database read, not from when the file was written.
//
// Re-saving an old reading must not make it look fresh: a VM address that stale
// is one that may belong to another machine by now.
func TestAgeComesFromTheDatabaseReadNotTheWrite(t *testing.T) {
	c := NewCache(t.TempDir())
	read := time.Now().Add(-30 * time.Minute)
	if err := c.Save(ShapeFarms, snapshotAt(read)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := c.Load(ShapeFarms, time.Now())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if age := got.Age(time.Now()); age < 29*time.Minute {
		t.Errorf("age = %v, want it measured from the read 30m ago", age)
	}
	if got.Fresh(time.Now()) {
		t.Error("a half-hour-old reading reports as fresh")
	}
	if !(Cached{CapturedAt: time.Now().Add(-time.Minute)}).Fresh(time.Now()) {
		t.Error("a one-minute-old reading does not report as fresh")
	}
}

// A snapshot with no read time is refused: a file claiming freshness when
// nothing knows when it was read is worse than no file.
func TestASnapshotWithNoReadTimeIsRefused(t *testing.T) {
	c := NewCache(t.TempDir())
	if err := c.Save(ShapeFarms, store.Fleet{}); err == nil {
		t.Error("a snapshot with no read time was stored")
	}
}

// Everything unusable is the same answer, because the caller's next move is the
// same: read the database.
func TestEverythingUnusableReadsAsAbsent(t *testing.T) {
	now := time.Now()

	t.Run("no file", func(t *testing.T) {
		if _, err := NewCache(t.TempDir()).Load(ShapeFarms, now); !errors.Is(err, ErrNoCache) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("older vctl wrote it", func(t *testing.T) {
		c := NewCache(t.TempDir())
		if err := c.Save(ShapeFarms, snapshotAt(now)); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(c.path(ShapeFarms))
		bumped := []byte(string(raw)[:len(`{"version":`)] + "99" + string(raw)[len(`{"version":1`):])
		if err := os.WriteFile(c.path(ShapeFarms), bumped, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Load(ShapeFarms, now); !errors.Is(err, ErrNoCache) {
			t.Errorf("a file from another version was accepted: %v", err)
		}
	})

	t.Run("corrupt", func(t *testing.T) {
		c := NewCache(t.TempDir())
		if err := os.MkdirAll(c.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.path(ShapeFarms), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Load(ShapeFarms, now); !errors.Is(err, ErrNoCache) {
			t.Errorf("a corrupt file was accepted: %v", err)
		}
	})

	t.Run("older than a day", func(t *testing.T) {
		c := NewCache(t.TempDir())
		if err := c.Save(ShapeFarms, snapshotAt(now.Add(-25*time.Hour))); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Load(ShapeFarms, now); !errors.Is(err, ErrNoCache) {
			t.Errorf("a day-old reading was served: %v", err)
		}
	})
}

// The two shapes are separate files. A light reading must not answer for a
// caller that needs VM rows — an empty instance list reads as a deployment with
// no VMs.
func TestTheTwoShapesDoNotOverwriteEachOther(t *testing.T) {
	c := NewCache(t.TempDir())
	now := time.Now()

	full := snapshotAt(now)
	if err := c.Save(ShapeVMs, full); err != nil {
		t.Fatal(err)
	}
	light := snapshotAt(now)
	light.Instances = nil
	if err := c.Save(ShapeFarms, light); err != nil {
		t.Fatal(err)
	}

	got, err := c.Load(ShapeVMs, now)
	if err != nil {
		t.Fatalf("Load(vms): %v", err)
	}
	if len(got.Fleet.Instances) == 0 {
		t.Error("a light write erased the instance rows a full read had stored")
	}
	if _, err := c.Load(ShapeFarms, now); err != nil {
		t.Errorf("Load(farms): %v", err)
	}
}

// The file is a map of the internal network. It holds no credential, and it
// still does not belong to anybody but its owner.
func TestTheFileIsPrivate(t *testing.T) {
	c := NewCache(t.TempDir())
	if err := c.Save(ShapeFarms, snapshotAt(time.Now())); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(c.path(ShapeFarms))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode %o, want 0600", perm)
	}
	di, err := os.Stat(filepath.Dir(c.path(ShapeFarms)))
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode %o, want 0700", perm)
	}
}

// Clearing is what a reconcile or a rename does, so a screen does not show what
// somebody just changed away from.
func TestClearRemovesBothShapesAndToleratesAbsence(t *testing.T) {
	c := NewCache(t.TempDir())
	now := time.Now()
	for _, s := range []Shape{ShapeFarms, ShapeVMs} {
		if err := c.Save(s, snapshotAt(now)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	for _, s := range []Shape{ShapeFarms, ShapeVMs} {
		if _, err := c.Load(s, now); !errors.Is(err, ErrNoCache) {
			t.Errorf("%s survived the clear", s)
		}
	}
	if err := c.Clear(); err != nil {
		t.Errorf("clearing an empty cache is an error: %v", err)
	}
}

// No credential of any kind reaches this file. The rows are network facts; a
// password in there would be a password on disk.
func TestNothingSecretIsStored(t *testing.T) {
	c := NewCache(t.TempDir())
	if err := c.Save(ShapeVMs, snapshotAt(time.Now())); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(c.path(ShapeVMs))
	if err != nil {
		t.Fatal(err)
	}
	for _, word := range []string{"password", "secret", "token", "private_key", "hvs."} {
		if containsFold(string(raw), word) {
			t.Errorf("the stored reading contains %q", word)
		}
	}
}

func containsFold(haystack, needle string) bool {
	h, n := []rune(haystack), []rune(needle)
	if len(n) == 0 || len(h) < len(n) {
		return false
	}
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// A shape has to mean one thing.
//
// Three readings exist — identity only, identity plus counts, and that plus the
// instance rows — and only the last two are supersets of ShapeFarms. Storing
// the identity-only one under it would make a later listing print every
// deployment as having zero VMs and never having reconciled, which reads as a
// fact about the fleet rather than as an artefact of which command ran first.
func TestAStoredFarmsReadingAlwaysCarriesCountsAndRuns(t *testing.T) {
	c := NewCache(t.TempDir())
	now := time.Now()
	if err := c.Save(ShapeFarms, snapshotAt(now)); err != nil {
		t.Fatal(err)
	}
	got, err := c.Load(ShapeFarms, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Fleet.VMs) == 0 {
		t.Error("the stored reading has no VM counts, so a listing from it would show zero")
	}
	if len(got.Fleet.Runs) == 0 {
		t.Error("the stored reading has no reconcile times, so every farm would read as never reconciled")
	}
	cat := From(got.Fleet)
	f, _ := cat.Find("10.0.0.1:5000")
	if cat.VMCount(f.ID) == 0 {
		t.Error("VM count came back zero through the cache")
	}
	if _, ok := cat.Reconciled(f.ID); !ok {
		t.Error("reconcile time was lost through the cache")
	}
}

// A shape is a floor. A caller wanting counts is answered by either reading, so
// it takes whichever is newer — a listing beside a browser that just refreshed
// must not read the older file and disagree with it for no visible reason.
func TestAskingForFarmsTakesWhicheverReadingIsNewer(t *testing.T) {
	c := NewCache(t.TempDir())
	old := time.Now().Add(-20 * time.Minute)
	recent := time.Now().Add(-1 * time.Minute)

	if err := c.Save(ShapeFarms, snapshotAt(old)); err != nil {
		t.Fatalf("Save farms: %v", err)
	}
	if err := c.Save(ShapeVMs, snapshotAt(recent)); err != nil {
		t.Fatalf("Save vms: %v", err)
	}
	got, err := c.LoadAtLeast(ShapeFarms, time.Now())
	if err != nil {
		t.Fatalf("LoadAtLeast: %v", err)
	}
	if !got.CapturedAt.Equal(recent) {
		t.Errorf("took the reading from %v, want the newer one from %v", got.CapturedAt, recent)
	}

	// And the other way round, so this is not just a preference for one file.
	if err := c.Save(ShapeFarms, snapshotAt(time.Now())); err != nil {
		t.Fatalf("Save farms: %v", err)
	}
	got, err = c.LoadAtLeast(ShapeFarms, time.Now())
	if err != nil {
		t.Fatalf("LoadAtLeast: %v", err)
	}
	if got.CapturedAt.Equal(recent) {
		t.Error("kept the vms reading after the farms one overtook it")
	}
}

// Instance rows can only come from the reading that has them. Answering with a
// farms reading would hand back an empty VM list that reads as a deployment
// with none in it.
func TestAskingForVMsIsNotAnsweredByAFarmsReading(t *testing.T) {
	c := NewCache(t.TempDir())
	if err := c.Save(ShapeFarms, snapshotAt(time.Now())); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := c.LoadAtLeast(ShapeVMs, time.Now()); !errors.Is(err, ErrNoCache) {
		t.Errorf("a farms reading answered a request for VMs: %v", err)
	}
	if err := c.Save(ShapeVMs, snapshotAt(time.Now())); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := c.LoadAtLeast(ShapeVMs, time.Now())
	if err != nil {
		t.Fatalf("LoadAtLeast: %v", err)
	}
	if len(got.Fleet.Instances) == 0 {
		t.Error("the reading that answered carries no instances")
	}
}

// Nothing stored is nothing to serve, whichever shape was asked for.
func TestLoadAtLeastWithNothingStored(t *testing.T) {
	c := NewCache(t.TempDir())
	for _, s := range []Shape{ShapeFarms, ShapeVMs} {
		if _, err := c.LoadAtLeast(s, time.Now()); !errors.Is(err, ErrNoCache) {
			t.Errorf("%s: %v", s, err)
		}
	}
}

// A reading from the future is not fresh, it is unreadable.
//
// The capture time comes from the database's clock and the age is measured
// against this machine's. When the database is ahead, Age goes negative and
// every window comparison passes — so a reading stamped an hour from now was
// served as fresh for an hour past its real expiry. That is the one direction a
// staleness check must not fail in.
func TestAReadingStampedInTheFutureIsRefused(t *testing.T) {
	c := NewCache(t.TempDir())
	if err := c.Save(ShapeFarms, snapshotAt(time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := c.Load(ShapeFarms, time.Now()); !errors.Is(err, ErrNoCache) {
		t.Errorf("an hour-ahead reading was served: %v", err)
	}
	// A few seconds between two synchronised clocks is normal and must not
	// throw a good reading away.
	if err := c.Save(ShapeFarms, snapshotAt(time.Now().Add(5*time.Second))); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := c.Load(ShapeFarms, time.Now()); err != nil {
		t.Errorf("ordinary clock skew discarded the reading: %v", err)
	}
}
