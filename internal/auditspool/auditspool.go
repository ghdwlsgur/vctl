// Package auditspool holds SSH access records that could not reach Postgres and
// replays them once it is back.
//
// The access-log write has always been best-effort: a failure warns and never
// blocks the connection (internal/access.Connector.audit). That was a reasonable
// trade while a database outage also stopped `vctl ssh` from resolving a host —
// the two failed together, so little went unrecorded. Serving inventory from a
// local snapshot breaks that coupling: connections now succeed for as long as the
// outage lasts, and every one of them would vanish. An access system that quietly
// stops recording exactly when it is being used the most is worse than one that
// fails loudly, so the records are kept locally and flushed later.
//
// This is an outbox, not a second source of truth. Nothing reads access history
// from here; Postgres remains the only place audit rows live.
package auditspool

import (
	"bufio"
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

// ErrFull means the spool has reached its size cap and refused the record.
//
// The cap retains the oldest entries and rejects new ones rather than evicting
// to make room. Both lose data, but a visible refusal — surfaced through the
// caller's audit-error warning — tells the operator the trail is incomplete,
// whereas silent eviction of the oldest records looks exactly like success.
var ErrFull = errors.New("audit spool is full")

// DefaultMaxBytes caps the spool. Rows are a few hundred bytes, so this holds
// well over ten thousand connections — far more than any plausible outage.
const DefaultMaxBytes int64 = 8 << 20 // 8 MiB

// Sink accepts a replayed record. Satisfied by *store.Store.
type Sink interface {
	LogAccess(ctx context.Context, e store.AccessEntry) error
}

// Spool is an append-only JSONL file of pending access records.
type Spool struct {
	Path     string
	MaxBytes int64
}

// New locates the spool under a state directory.
func New(stateDir string) *Spool {
	return &Spool{
		Path:     filepath.Join(stateDir, "spool", "access.jsonl"),
		MaxBytes: DefaultMaxBytes,
	}
}

// Append records one entry for later replay, stamping SignedAt when the caller
// left it zero so the row keeps the time of the connection rather than the time
// of the flush.
func (s *Spool) Append(e store.AccessEntry) error {
	if s == nil || s.Path == "" {
		return errors.New("auditspool: no path configured")
	}
	if e.SignedAt.IsZero() {
		e.SignedAt = time.Now().UTC()
	}
	if err := securefile.EnsurePrivateDir(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	if full, err := s.atCap(); err != nil {
		return err
	} else if full {
		return fmt.Errorf("%w (%s) — the trail is incomplete until it is flushed", ErrFull, s.Path)
	}

	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// atCap measures the live spool together with any claim files a failing drain
// left behind. Counting only the live file would let the total grow without
// bound whenever the database stays down long enough for drains to keep failing.
func (s *Spool) atCap() (bool, error) {
	batches, err := s.batches()
	if err != nil {
		return false, err
	}
	var total int64
	for _, path := range append(batches, s.Path) {
		fi, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		total += fi.Size()
	}
	max := s.MaxBytes
	if max <= 0 {
		max = DefaultMaxBytes
	}
	return total >= max, nil
}

// Pending reports how many records are waiting, counting both the live spool and
// any batches a previous drain claimed but did not finish.
func (s *Spool) Pending() (int, error) {
	total := 0
	batches, err := s.batches()
	if err != nil {
		return 0, err
	}
	for _, path := range append(batches, s.Path) {
		entries, err := s.load(path)
		if err != nil {
			return total, err
		}
		total += len(entries)
	}
	return total, nil
}

// Drain replays every pending record into sink and returns how many landed.
//
// It claims work by renaming the spool aside before reading it. That rename is
// atomic, so a concurrent `vctl ssh` in another terminal appends to a fresh file
// that this drain will never rewrite. The obvious implementation — read the
// file, send, then write back what is left — silently destroys anything appended
// in between, which for audit records is the one outcome worth engineering
// against.
//
// A partially flushed batch stays on disk under its claim name and is retried
// first by the next drain, so a database that disappears mid-flush costs
// nothing.
func (s *Spool) Drain(ctx context.Context, sink Sink) (int, error) {
	batches, err := s.batches()
	if err != nil {
		return 0, err
	}
	if claimed, err := s.claim(); err != nil {
		return 0, err
	} else if claimed != "" {
		batches = append(batches, claimed)
	}

	sent := 0
	for _, path := range batches {
		n, err := s.drainBatch(ctx, sink, path)
		sent += n
		if err != nil {
			return sent, err
		}
	}
	return sent, nil
}

// claim renames the live spool aside so appends racing this drain land in a new
// file. It returns "" when there is nothing to claim.
//
// The name must be unique per claim, not per process. Deriving it from the PID
// looked sufficient and was not: a drain that fails leaves its batch behind, and
// the next drain from the same process would rename the new spool straight over
// it, destroying every record in the batch it was supposed to retry. A reserved
// temp name cannot collide with an existing batch or with a concurrent drain.
func (s *Spool) claim() (string, error) {
	if _, err := os.Stat(s.Path); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), filepath.Base(s.Path)+".*"+claimSuffix)
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	tmp.Close()
	if err := os.Rename(s.Path, name); err != nil {
		_ = os.Remove(name)
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil // another drain claimed it first
		}
		return "", err
	}
	return name, nil
}

const claimSuffix = ".claim"

// batches lists claim files left behind by earlier drains. They are retried
// before newly queued records so a failed batch cannot starve.
//
// The order among several batches is by name, which is arbitrary — claim names
// are reserved, not sequenced. That is fine: audit rows carry the time of the
// connection in SignedAt, so the audit log reads chronologically regardless of
// the order rows are inserted.
func (s *Spool) batches() ([]string, error) {
	matches, err := filepath.Glob(s.Path + ".*" + claimSuffix)
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

// drainBatch replays one claimed file, rewriting it with the unsent remainder if
// the sink fails partway and removing it once empty.
func (s *Spool) drainBatch(ctx context.Context, sink Sink, path string) (int, error) {
	entries, err := s.load(path)
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, remove(path)
	}
	sent := 0
	for _, e := range entries {
		if err := sink.LogAccess(ctx, e); err != nil {
			if rewriteErr := securefile.WriteAtomic(path, encode(entries[sent:]), 0o600); rewriteErr != nil {
				return sent, fmt.Errorf("flush stopped after %d: %w (and re-queueing the remainder failed: %v)", sent, err, rewriteErr)
			}
			return sent, fmt.Errorf("flush stopped after %d of %d: %w", sent, len(entries), err)
		}
		sent++
	}
	return sent, remove(path)
}

// load parses one spool file. A truncated or corrupt final line — a crash
// mid-append — is skipped rather than failing the whole flush: losing one record
// beats losing every record behind it.
func (s *Spool) load(path string) ([]store.AccessEntry, error) {
	if s == nil || path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []store.AccessEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e store.AccessEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// encode renders entries back to JSONL.
func encode(entries []store.AccessEntry) []byte {
	var buf []byte
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			continue
		}
		buf = append(append(buf, line...), '\n')
	}
	return buf
}

// remove deletes a spool file, tolerating one that is already gone.
func remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
