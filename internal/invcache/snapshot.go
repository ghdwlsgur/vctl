package invcache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ghdwlsgur/vctl/internal/securefile"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// snapshotVersion is bumped whenever the on-disk shape changes. A snapshot
// written by a different version is discarded rather than migrated: it is a
// cache, so the cost of throwing it away is one online command.
const snapshotVersion = 1

// GrantRecord is one identity's app-RBAC command grants as of the last time they
// could be read from Postgres.
//
// Grants are cached, unlike Vault policies, because without them every mutate
// command would be denied the moment the database blinks — which defeats the
// point. The mitigation is time: CapturedAt bounds how long an offline decision
// may lean on them (see authz's offline TTL), so a revoked grant cannot outlive
// the window even on a laptop that never reconnects.
type GrantRecord struct {
	Commands   []string
	CapturedAt time.Time
}

// GrantRecord deliberately has no Has method. Deciding whether a cached grant
// covers a command — the "*" wildcard included — belongs to authz.CachedGrant,
// the single owner of that rule; a second copy here is how the two drifted
// apart the first time.

// Snapshot is the whole local cache: inventory with its last known runtime
// status, plus per-identity command grants.
//
// Status is captured alongside inventory even though it is live-by-definition
// data. Dropping it would make an offline `vctl list` claim every host has no
// agent, which reads as a fleet-wide outage; keeping it, and rendering it as
// aged rather than current, is the honest option.
//
// CapturedAt means one thing only: when Servers was read from Postgres. It is
// deliberately NOT "when this file was written". Grants are confirmed on their
// own schedule and carry their own timestamps, so a snapshot that holds grants
// and no inventory keeps a zero CapturedAt — otherwise it would read as freshly
// captured and suppress the inventory refresh it is actually waiting for.
type Snapshot struct {
	Version    int
	CapturedAt time.Time
	Servers    []store.ServerWithStatus
	Grants     map[string]GrantRecord
}

// Age reports how long ago the inventory was captured. Meaningful only when
// HasInventory reports true; check that first.
func (s *Snapshot) Age(now time.Time) time.Duration { return now.Sub(s.CapturedAt) }

// HasInventory reports whether the snapshot can actually answer host lookups.
//
// A snapshot holding only grants is not usable inventory. Serving it would make
// an outage look like an empty inventory and send the operator off to run
// `vctl sync` — the one thing that cannot work while the database is down.
func (s *Snapshot) HasInventory() bool {
	return s != nil && !s.CapturedAt.IsZero() && len(s.Servers) > 0
}

// NeedsRefresh reports whether an online command should re-capture the
// inventory: either there is none, or what there is has aged past interval.
func (s *Snapshot) NeedsRefresh(now time.Time, interval time.Duration) bool {
	return !s.HasInventory() || s.Age(now) >= interval
}

// Expired reports whether the inventory is too old to serve at all. maxAge <= 0
// means no limit.
//
// The cap exists because host topology drifts: an address that pointed at one
// machine last month can point at another today, and an access tool that
// silently routes an operator by month-old data is worse than one that refuses.
func (s *Snapshot) Expired(now time.Time, maxAge time.Duration) bool {
	return maxAge > 0 && s.HasInventory() && s.Age(now) > maxAge
}

// SetInventory replaces the captured hosts and stamps the capture time. It is
// the only thing that moves CapturedAt.
func (s *Snapshot) SetInventory(servers []store.ServerWithStatus, now time.Time) {
	sortServers(servers)
	s.Servers = servers
	s.CapturedAt = now
}

// Grant returns the cached grants for an identity.
func (s *Snapshot) Grant(identity string) (GrantRecord, bool) {
	if s == nil || s.Grants == nil {
		return GrantRecord{}, false
	}
	g, ok := s.Grants[identity]
	return g, ok
}

// SetGrants records one identity's grants, stamped now.
func (s *Snapshot) SetGrants(identity string, commands []string, now time.Time) {
	if identity == "" {
		return
	}
	if s.Grants == nil {
		s.Grants = map[string]GrantRecord{}
	}
	sorted := append([]string(nil), commands...)
	sort.Strings(sorted)
	s.Grants[identity] = GrantRecord{Commands: sorted, CapturedAt: now}
}

// Capture reads the full inventory through r into snap, preserving whatever
// else the snapshot already holds (grants).
//
// One query (ListWithStatus with no DC filter) covers both listing views:
// InventoryRow is derived from ServerWithStatus rather than fetched separately.
//
// An empty result is refused rather than stored. Postgres answering with zero
// hosts is indistinguishable here from a misconfigured read, and overwriting a
// good snapshot with nothing would turn a working offline fallback into a dead
// one at exactly the wrong moment.
func Capture(ctx context.Context, r Reader, snap *Snapshot, now time.Time) error {
	servers, err := r.ListWithStatus(ctx, "")
	if err != nil {
		return fmt.Errorf("snapshot inventory: %w", err)
	}
	if len(servers) == 0 {
		return fmt.Errorf("snapshot inventory: database returned no hosts")
	}
	snap.SetInventory(servers, now)
	return nil
}

// sortServers orders rows by (dc, hostname) — the ordering the Postgres listing
// queries use, so a snapshot round-trip does not reshuffle output.
func sortServers(rows []store.ServerWithStatus) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].DC != rows[j].DC {
			return rows[i].DC < rows[j].DC
		}
		return rows[i].Hostname < rows[j].Hostname
	})
}

// FileStore persists snapshots to one path with owner-only permissions.
//
// The file is not secret — inventory holds no credentials — but it is a complete
// map of the internal network, so it is kept at 0600 in the private state dir
// rather than anywhere world-readable.
type FileStore struct{ Path string }

// NewFileStore locates the snapshot under a state directory.
func NewFileStore(stateDir string) *FileStore {
	return &FileStore{Path: filepath.Join(stateDir, "cache", "inventory.json")}
}

// Load reads the snapshot. A missing file, an unreadable one, or a version
// mismatch all report ErrNoSnapshot: every one of them means "nothing usable
// here", and the caller's next move is the same.
func (f *FileStore) Load() (*Snapshot, error) {
	if f == nil || f.Path == "" {
		return nil, ErrNoSnapshot
	}
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoSnapshot
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoSnapshot, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrNoSnapshot, err)
	}
	if snap.Version != snapshotVersion {
		return nil, fmt.Errorf("%w: version %d (want %d)", ErrNoSnapshot, snap.Version, snapshotVersion)
	}
	return &snap, nil
}

// Update applies fn to the stored snapshot and writes the result back, creating
// an empty snapshot first when there is nothing on disk. fn returning an error
// abandons the write.
//
// This is the only sanctioned way to mutate the cache, because the two callers
// that do — an inventory refresh and a grant confirmation — touch different
// fields of the same file and previously each reimplemented load/merge/save.
//
// Concurrency: writes are atomic (temp + rename), so a reader never sees a torn
// file, but two processes updating at once is last-writer-wins. That is
// deliberate. The failure it can produce is a dropped grant confirmation or an
// inventory reverted to the previous capture — both self-correct on the next
// online command, and neither is worth making every vctl invocation wait on a
// lock that a hung process could hold.
func (f *FileStore) Update(fn func(*Snapshot) error) error {
	snap, err := f.Load()
	if err != nil {
		snap = &Snapshot{}
	}
	if err := fn(snap); err != nil {
		return err
	}
	return f.Save(snap)
}

// Save writes the snapshot atomically at 0600, creating the cache directory.
func (f *FileStore) Save(snap *Snapshot) error {
	if f == nil || f.Path == "" {
		return errors.New("invcache: no snapshot path configured")
	}
	if snap == nil {
		return errors.New("invcache: nil snapshot")
	}
	snap.Version = snapshotVersion
	if err := securefile.EnsurePrivateDir(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	return securefile.WriteAtomic(f.Path, b, 0o600)
}

// Clear removes the snapshot. A missing file is not an error.
func (f *FileStore) Clear() error {
	if f == nil || f.Path == "" {
		return nil
	}
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
