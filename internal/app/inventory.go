package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/ghdwlsgur/vctl/internal/auditspool"
	"github.com/ghdwlsgur/vctl/internal/invcache"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// Inventory is an open read handle over the host inventory. It reads from
// Postgres when Postgres answers and from the local snapshot when it does not,
// behind one interface so commands need no branch of their own — only a decision
// about how to label the result, which Mode carries.
type Inventory struct {
	invcache.Reader
	Mode invcache.Mode
	// Snap is the snapshot backing a cached read; nil when live.
	Snap  *invcache.Snapshot
	close func()
}

// Close releases the handle. Safe on a cached (connectionless) inventory.
func (i *Inventory) Close() {
	if i != nil && i.close != nil {
		i.close()
	}
}

// Cached reports whether answers come from the local snapshot.
func (i *Inventory) Cached() bool { return i != nil && i.Mode == invcache.ModeCached }

// Age reports how old the backing snapshot is; zero when live.
func (i *Inventory) Age(now time.Time) time.Duration {
	if i == nil || i.Snap == nil {
		return 0
	}
	return i.Snap.Age(now)
}

// CacheFile is where this app persists its inventory snapshot.
func (a *App) CacheFile() *invcache.FileStore { return invcache.NewFileStore(a.Cfg.StateDir) }

// ErrCacheDisabled reports that the local snapshot is switched off, so nothing
// will be read from or written to it.
var ErrCacheDisabled = errors.New("the local cache is disabled (VCTL_CACHE_DISABLE / cache_disabled)")

// updateCache applies fn to the stored snapshot, refusing when the cache is
// switched off. Every mutation of the snapshot goes through here so the
// disabled check exists once instead of at each call site, where one omission
// would quietly keep writing a cache the operator asked vctl not to keep.
func (a *App) updateCache(fn func(*invcache.Snapshot) error) error {
	if a.Cfg.CacheDisabled {
		return ErrCacheDisabled
	}
	return a.CacheFile().Update(fn)
}

// readCache loads the stored snapshot, treating a disabled cache as an absent
// one.
func (a *App) readCache() (*invcache.Snapshot, error) {
	if a.Cfg.CacheDisabled {
		return nil, ErrCacheDisabled
	}
	return a.CacheFile().Load()
}

// Spool is where this app queues access records that could not reach Postgres.
func (a *App) Spool() *auditspool.Spool { return auditspool.New(a.Cfg.StateDir) }

// OpenInventory opens the inventory for reading, preferring Postgres and falling
// back to the local snapshot.
//
// On the live path it also refreshes the snapshot when it has aged past
// cache_refresh, which is what keeps the offline copy current without a separate
// sync step: ordinary use is the refresh. The refresh is best-effort — a
// snapshot that cannot be written must never fail the command the operator
// actually ran.
func (a *App) OpenInventory(ctx context.Context) (*Inventory, error) {
	if snap := a.snapshotToServeInstead(ctx); snap != nil {
		return cachedInventory(snap), nil
	}
	st, err := a.OpenStore(ctx, PurposeInventoryRead)
	if err == nil {
		a.RefreshSnapshot(ctx, st)
		return &Inventory{Reader: st, Mode: invcache.ModeLive, close: st.Close}, nil
	}
	snap, loadErr := a.readCache()
	if loadErr != nil {
		return nil, err
	}
	if fallbackErr := a.snapshotUsable(snap); fallbackErr != nil {
		return nil, fmt.Errorf("%w (local snapshot unusable: %v)", err, fallbackErr)
	}
	return cachedInventory(snap), nil
}

func cachedInventory(snap *invcache.Snapshot) *Inventory {
	return &Inventory{Reader: invcache.NewMemory(snap), Mode: invcache.ModeCached, Snap: snap}
}

// dbProbeTimeout bounds the reachability check below. It only has to answer
// "is anything accepting TCP here", which a healthy database does immediately
// even under load — the slow parts are the handshake and the query, not the
// accept.
const dbProbeTimeout = 2 * time.Second

// snapshotToServeInstead returns a usable snapshot when going to Postgres would
// first drag the operator through an interactive login that cannot help.
//
// Opening the store authenticates before it dials, so during an outage with a
// lapsed token the operator gets a browser SSO prompt and only then learns the
// database is down. Nothing about logging in makes an unreachable database
// reachable, so when a prompt is what stands in the way — and only then — the
// database is probed directly and the snapshot served if it does not answer.
//
// Deliberately narrow. With a valid token, or with AppRole credentials that
// authenticate silently, there is no prompt to avoid and this costs nothing:
// the probe never runs and the normal path is unchanged.
func (a *App) snapshotToServeInstead(ctx context.Context) *invcache.Snapshot {
	if !a.WouldPromptForLogin() {
		return nil
	}
	snap, err := a.readCache()
	if err != nil || a.snapshotUsable(snap) != nil {
		return nil // nothing worth serving; take the normal path and report properly
	}
	if a.databaseAccepts(ctx) {
		return nil
	}
	return snap
}

// WouldPromptForLogin reports whether authenticating right now would put an
// interactive prompt in front of the operator. A cached token or AppRole
// credentials both authenticate without one, and the local-DSN escape hatch
// skips Vault entirely.
//
// Exported for shell completion, which asks the same question for the opposite
// reason. The snapshot path asks whether a prompt is coming so it can answer
// from disk instead; a completion asks so it can decline, because a password
// prompt attached to a Tab keypress has nowhere to appear.
func (a *App) WouldPromptForLogin() bool {
	if a.Cfg.LocalDBDSN != "" {
		return false // OpenStore takes the static-credential path; Vault is not consulted
	}
	if a.Vault.HasValidToken() {
		return false
	}
	_, _, haveAppRole := a.AppRoleCreds()
	return !haveAppRole
}

// databaseAccepts reports whether anything is listening at the inventory
// database endpoint. An endpoint it cannot determine counts as reachable, so an
// unparseable DSN falls through to the real connection attempt and its real
// error rather than being silently answered from cache.
func (a *App) databaseAccepts(ctx context.Context) bool {
	endpoint := a.dbEndpoint()
	if endpoint == "" {
		return true
	}
	conn, err := (&net.Dialer{Timeout: dbProbeTimeout}).DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// dbEndpoint is the host:port the inventory store would dial, or "" when it
// cannot be determined.
func (a *App) dbEndpoint() string {
	if a.Cfg.LocalDBDSN != "" {
		endpoint, err := store.DSNEndpoint(a.Cfg.LocalDBDSN)
		if err != nil {
			return ""
		}
		return endpoint
	}
	if a.Cfg.DBHost == "" {
		return ""
	}
	return net.JoinHostPort(a.Cfg.DBHost, strconv.Itoa(a.Cfg.DBPort))
}

// snapshotUsable reports why a snapshot must not be served, or nil when it may
// be.
//
// Both rejections exist to avoid answering a question with something that only
// looks like an answer. A snapshot holding grants but no hosts would surface as
// "inventory is empty — run 'vctl sync'", pointing the operator at a command
// that cannot work during the very outage they are in. An expired one would
// route them by topology old enough to have been reassigned. In both cases the
// caller reports the database failure instead, which is the actionable fact.
func (a *App) snapshotUsable(snap *invcache.Snapshot) error {
	if !snap.HasInventory() {
		return errors.New("holds no hosts yet")
	}
	now := time.Now()
	if maxAge := a.Cfg.CacheStaleLimit(); snap.Expired(now, maxAge) {
		return fmt.Errorf("captured %s ago, past the %s limit — reconnect to refresh it, or set cache_max_age",
			ui.CompactDuration(snap.Age(now)), ui.CompactDuration(maxAge))
	}
	return nil
}

// RefreshSnapshot re-captures the inventory into the local snapshot when it has
// aged past cache_refresh. Grants are left untouched: they are confirmed on
// their own schedule, and an inventory refresh must not revoke a user's offline
// authorization.
//
// Best-effort by contract — every error is swallowed. It runs as a side effect
// of commands the operator ran for another reason, so a cache problem must not
// become their problem.
func (a *App) RefreshSnapshot(ctx context.Context, r invcache.Reader) {
	now := time.Now()
	_ = a.updateCache(func(snap *invcache.Snapshot) error {
		if !snap.NeedsRefresh(now, a.Cfg.CacheRefreshInterval()) {
			return errSkipUpdate
		}
		return invcache.Capture(ctx, r, snap, now)
	})
}

// CaptureSnapshot re-captures the inventory unconditionally, for `vctl cache
// refresh`. It reports failure, unlike the automatic path: the operator asked
// for this one.
func (a *App) CaptureSnapshot(ctx context.Context, r invcache.Reader) (*invcache.Snapshot, error) {
	var captured *invcache.Snapshot
	err := a.updateCache(func(snap *invcache.Snapshot) error {
		if err := invcache.Capture(ctx, r, snap, time.Now()); err != nil {
			return err
		}
		captured = snap
		return nil
	})
	return captured, err
}

// errSkipUpdate abandons a snapshot update without reporting a failure — the
// "nothing to do" path through Update.
var errSkipUpdate = errors.New("snapshot update not needed")

// RecordGrants caches one identity's command grants after a successful online
// lookup, stamped now so the offline window is measured from a point where
// Postgres actually confirmed them.
//
// It never stamps the inventory capture time. A run that records grants before
// any inventory has been captured must leave the snapshot looking un-captured,
// or the refresh that follows will decide it has nothing to do.
func (a *App) RecordGrants(identity string, commands []string) {
	if identity == "" {
		return
	}
	now := time.Now()
	_ = a.updateCache(func(snap *invcache.Snapshot) error {
		snap.SetGrants(identity, commands, now)
		return nil
	})
}

// CachedGrants returns an identity's last confirmed grants.
func (a *App) CachedGrants(identity string) (invcache.GrantRecord, bool) {
	snap, err := a.readCache()
	if err != nil {
		return invcache.GrantRecord{}, false
	}
	return snap.Grant(identity)
}

// SpooledError reports that an access record could not reach Postgres and was
// queued locally instead. Callers distinguish it from a plain audit failure so
// the operator learns the record is pending rather than lost.
type SpooledError struct {
	Cause   error
	Pending int
}

func (e *SpooledError) Error() string { return e.Cause.Error() }
func (e *SpooledError) Unwrap() error { return e.Cause }

// spoolAccess queues an entry after a failed Postgres write. If queueing also
// fails, the original database error is returned — the record is genuinely lost
// and that is what the caller must be told.
func (a *App) spoolAccess(entry store.AccessEntry, cause error) error {
	sp := a.Spool()
	if err := sp.Append(entry); err != nil {
		return cause
	}
	pending, _ := sp.Pending()
	return &SpooledError{Cause: cause, Pending: pending}
}

// drainSpool replays queued records through a writer that just proved it works.
// Reported through OnSpoolFlush rather than returned: the caller's own audit
// write already succeeded, and a catch-up failure must not turn that into an
// error.
func (a *App) drainSpool(ctx context.Context, sink auditspool.Sink) {
	sp := a.Spool()
	if n, err := sp.Pending(); err != nil || n == 0 {
		return
	}
	sent, err := sp.Drain(ctx, sink)
	if a.OnSpoolFlush != nil && (sent > 0 || err != nil) {
		a.OnSpoolFlush(sent, err)
	}
}
