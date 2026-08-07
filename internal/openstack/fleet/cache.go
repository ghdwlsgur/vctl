package fleet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ghdwlsgur/vctl/internal/securefile"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// A reading of the fleet, kept on disk so the next screen does not have to pay
// for one.
//
// Measured on this workstation with --debug-timing: the query is 1.5% of a
// listing and everything else is authenticating to Vault, minting a Postgres
// credential and completing a TLS handshake — about 200ms on a good day and
// ten seconds when the path to the load balancer is unhappy. Caching the rows
// skips all of it, and the day it saves ten seconds is the day the tool is
// hardest to use.
//
// Deliberately not merged into inventory.json. That file keeps `vctl ssh`
// working through a Postgres outage, and it is the wrong thing to risk for a
// listing: the two differ in size, in how often they turn over, in how stale
// they may acceptably be, and a version bump or a corrupt write here must not
// take SSH down with it.
//
// Nothing secret is stored. The rows are hostnames, addresses and roles — no
// credential of any kind reaches this file — but together they are a map of the
// internal network, so it is 0600 in the private state directory like its
// neighbour.

// cacheVersion is bumped whenever the stored shape changes. A file written by
// an older vctl is discarded rather than guessed at: a field that moved would
// otherwise read as an empty value, and an empty deployment list is
// indistinguishable from a fleet nobody has probed.
const cacheVersion = 1

// FreshFor is how long a reading is served without question.
//
// Five minutes, matched to the heartbeat: hosts report on that period, so a
// cache younger than one cycle cannot be behind by more than one report. The
// deployments themselves turn over far slower — a reconcile runs every six
// hours — so the VM and farm rows are effectively still current well past this.
//
// Past it the reading is not thrown away. It is shown with its age and
// refreshed behind the screen, because a listing that is four minutes old and
// says so is more useful than a spinner.
const FreshFor = 5 * time.Minute

// UsableFor is the ceiling for serving a reading at all.
//
// A day-old picture of which host runs what is still worth showing when the
// database cannot be reached — that is most of the value here. Past a day it is
// not, and pretending otherwise routes somebody by a topology that has had a
// working day to change.
const UsableFor = 24 * time.Hour

// Shape says which reading a file holds.
//
// Two files rather than one with a flag, because the difference is what was
// fetched: a light reading has counts where the full one has instance rows. One
// file would mean a light write silently discarding VM rows a full read had
// stored, and a caller asking for VMs getting an empty list that looks like a
// deployment with none.
type Shape string

const (
	// ShapeFarms is deployments, hosts, counts and runs — what a listing or a
	// picker needs.
	ShapeFarms Shape = "farms"
	// ShapeVMs is the above plus the instance rows, for the screen that lists
	// them.
	ShapeVMs Shape = "vms"
)

// ErrNoCache means there is nothing usable on disk: no file, an unreadable one,
// a version from another vctl, or a reading old enough to be misleading. Every
// one of them leads the caller to the same next move — read the database — so
// they are one error.
var ErrNoCache = errors.New("no usable fleet cache")

// Cached is one stored reading.
type Cached struct {
	Version int `json:"version"`
	Shape   Shape

	// CapturedAt is when the *database* took the snapshot, not when this file
	// was written. Age is measured from it, because that is what the numbers on
	// screen are as old as. Measuring from the write would make a re-save of an
	// old reading look fresh, and a VM's address that stale is one that may
	// belong to another machine by now.
	CapturedAt time.Time   `json:"captured_at"`
	Fleet      store.Fleet `json:"fleet"`
}

// Age is how old the reading is.
func (c Cached) Age(now time.Time) time.Duration { return now.Sub(c.CapturedAt) }

// Fresh reports whether it can be served without a word.
func (c Cached) Fresh(now time.Time) bool { return c.Age(now) < FreshFor }

// Cache is where readings are kept.
type Cache struct{ Dir string }

// NewCache locates the files under a state directory, beside the inventory
// snapshot.
func NewCache(stateDir string) *Cache {
	return &Cache{Dir: filepath.Join(stateDir, "cache")}
}

func (c *Cache) path(s Shape) string {
	return filepath.Join(c.Dir, "openstack-fleet-"+string(s)+".json")
}

// Load returns the stored reading, or ErrNoCache.
//
// A reading past UsableFor is reported as absent rather than returned with a
// warning: a caller that has to decide whether to trust what it was handed will
// eventually decide wrong.
func (c *Cache) Load(s Shape, now time.Time) (Cached, error) {
	var out Cached
	if c == nil || c.Dir == "" {
		return out, ErrNoCache
	}
	b, err := os.ReadFile(c.path(s))
	if errors.Is(err, fs.ErrNotExist) {
		return out, ErrNoCache
	}
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrNoCache, err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, fmt.Errorf("%w: parse: %v", ErrNoCache, err)
	}
	if out.Version != cacheVersion {
		return out, fmt.Errorf("%w: version %d (want %d)", ErrNoCache, out.Version, cacheVersion)
	}
	if out.CapturedAt.IsZero() {
		return out, fmt.Errorf("%w: no capture time", ErrNoCache)
	}
	if out.Age(now) > UsableFor {
		return out, fmt.Errorf("%w: captured %s ago", ErrNoCache, out.Age(now).Round(time.Minute))
	}
	out.Shape = s
	return out, nil
}

// Save stores a reading, atomically and at 0600.
//
// The snapshot's own ReadAt is the capture time. A snapshot without one is
// refused rather than stamped with the current clock: a file claiming to be
// fresh when nothing knows when it was read is worse than no file.
func (c *Cache) Save(s Shape, snap store.Fleet) error {
	if c == nil || c.Dir == "" {
		return errors.New("fleet: no cache directory configured")
	}
	if snap.ReadAt.IsZero() {
		return errors.New("fleet: snapshot has no read time")
	}
	if err := securefile.EnsurePrivateDir(c.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(Cached{Version: cacheVersion, CapturedAt: snap.ReadAt, Fleet: snap})
	if err != nil {
		return err
	}
	return securefile.WriteAtomic(c.path(s), b, 0o600)
}

// Clear removes both readings. A missing file is not an error.
//
// Used after anything that makes the stored picture wrong — a reconcile, a farm
// rename — rather than leaving a screen to show what somebody just changed away
// from.
func (c *Cache) Clear() error {
	if c == nil || c.Dir == "" {
		return nil
	}
	for _, s := range []Shape{ShapeFarms, ShapeVMs} {
		if err := os.Remove(c.path(s)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
