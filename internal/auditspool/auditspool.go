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

// BatchSink is a Sink that can land many records in one network round trip.
// Optional: the drain uses it when the sink offers it. The spool replays
// inside whatever interactive command first gets a working audit connection —
// the ssh that happens to run right after an outage pays for the backlog —
// and a record-per-round-trip drain of a full spool costs most of a minute;
// chunks cost round trips in the tens.
//
// All-or-nothing per call: an error means nothing in that call landed, so the
// caller may requeue the whole chunk without duplicating rows. *store.Store
// satisfies this with a single-Sync pgx batch.
type BatchSink interface {
	LogAccessBatch(ctx context.Context, entries []store.AccessEntry) error
}

// Result is what one Drain accomplished.
type Result struct {
	// Sent is how many records landed in the sink.
	Sent int

	// Skipped is how many lines were dropped as unreadable: a write torn by a
	// crash, or a spool version this binary does not know. They are gone —
	// and saying so is the point, because a bare Sent count reads as a
	// complete recovery when it may not be one.
	Skipped int
}

const (
	// replayChunk is how many records one BatchSink round trip carries. Large
	// enough that even a full spool is tens of round trips, small enough that
	// a failed chunk requeues without a gap anyone notices.
	replayChunk = 500

	// maxDrainPerCall bounds what one Drain attempts, so the command that
	// happens to run first after an outage pays a bounded slice of the
	// backlog. What is left stays claimed on disk and the next command
	// continues from there — the claim files already carry retries across
	// processes, so the cap rides the same mechanism.
	maxDrainPerCall = 10_000
)

// Spool is an append-only JSONL file of pending access records.
type Spool struct {
	Path     string
	MaxBytes int64

	// maxPerDrain overrides maxDrainPerCall when positive. Tests only — the
	// production cap would need ten thousand fsynced appends to exercise.
	maxPerDrain int
}

// spoolVersion stamps every line written from here on, so a future format
// change is detected instead of guessed at.
const spoolVersion = 1

// spoolLine is the on-disk schema, owned by this package. Marshaling
// store.AccessEntry directly bound the disk format to that struct's Go field
// names — it carries no json tags — so renaming a field would have silently
// zeroed that column in every record still queued from an outage. The
// explicit tags here are the contract; the store struct stays free to change.
type spoolLine struct {
	V          int       `json:"v"`
	VaultUser  string    `json:"vault_user"`
	Hostname   string    `json:"hostname"`
	CertSerial string    `json:"cert_serial"`
	SignedAt   time.Time `json:"signed_at"`
	OK         bool      `json:"ok"`
	SourceIP   string    `json:"source_ip"`
	SourceAddr string    `json:"source_addr"`
	ClientHost string    `json:"client_host"`
	ClientUser string    `json:"client_user"`
	TargetAddr string    `json:"target_addr"`
	JumpVia    string    `json:"jump_via"`
	Error      string    `json:"error"`
}

func toLine(e store.AccessEntry) spoolLine {
	return spoolLine{
		V:         spoolVersion,
		VaultUser: e.VaultUser, Hostname: e.Hostname, CertSerial: e.CertSerial,
		SignedAt: e.SignedAt, OK: e.OK, SourceIP: e.SourceIP, SourceAddr: e.SourceAddr,
		ClientHost: e.ClientHost, ClientUser: e.ClientUser, TargetAddr: e.TargetAddr,
		JumpVia: e.JumpVia, Error: e.Error,
	}
}

func (l spoolLine) entry() store.AccessEntry {
	return store.AccessEntry{
		VaultUser: l.VaultUser, Hostname: l.Hostname, CertSerial: l.CertSerial,
		SignedAt: l.SignedAt, OK: l.OK, SourceIP: l.SourceIP, SourceAddr: l.SourceAddr,
		ClientHost: l.ClientHost, ClientUser: l.ClientUser, TargetAddr: l.TargetAddr,
		JumpVia: l.JumpVia, Error: l.Error,
	}
}

// decodeLine reads one spool line of any known format. ok is false for a line
// this binary cannot read: torn json, or a version stamp it does not know.
func decodeLine(line []byte) (store.AccessEntry, bool) {
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return store.AccessEntry{}, false
	}
	switch probe.V {
	case 0:
		// Written before the version stamp existed: store.AccessEntry under
		// its Go field names. Read until the last of them flushes.
		var e store.AccessEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return store.AccessEntry{}, false
		}
		return e, true
	case spoolVersion:
		var l spoolLine
		if err := json.Unmarshal(line, &l); err != nil {
			return store.AccessEntry{}, false
		}
		return l.entry(), true
	default:
		// A future binary's format. Guessing at its fields could write a
		// wrong audit row, which is worse than an honestly counted loss.
		return store.AccessEntry{}, false
	}
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

	line, err := json.Marshal(toLine(e))
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

// Pending reports how many replayable records are waiting, counting both the
// live spool and any batches a previous drain claimed but did not finish.
// Unreadable lines are not counted here — Drain reports them as Skipped.
func (s *Spool) Pending() (int, error) {
	total := 0
	batches, err := s.batches()
	if err != nil {
		return 0, err
	}
	for _, path := range append(batches, s.Path) {
		entries, _, err := s.load(path)
		if err != nil {
			return total, err
		}
		total += len(entries)
	}
	return total, nil
}

// HasBacklog reports whether anything is on disk at all — including files
// holding only unreadable lines, which a replayable-record count would never
// surface while they kept counting against the size cap. It stats rather than
// parses, because callers gate every successful audit write on it.
func (s *Spool) HasBacklog() (bool, error) {
	batches, err := s.batches()
	if err != nil {
		return false, err
	}
	for _, path := range append(batches, s.Path) {
		fi, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if fi.Size() > 0 {
			return true, nil
		}
	}
	return false, nil
}

// Drain replays pending records into sink and reports what happened.
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
// nothing. The same applies past the per-call cap: what this call did not
// attempt stays claimed for the next one.
func (s *Spool) Drain(ctx context.Context, sink Sink) (Result, error) {
	var res Result
	batches, err := s.batches()
	if err != nil {
		return res, err
	}
	if claimed, err := s.claim(); err != nil {
		return res, err
	} else if claimed != "" {
		batches = append(batches, claimed)
	}

	budget := maxDrainPerCall
	if s.maxPerDrain > 0 {
		budget = s.maxPerDrain
	}
	for _, path := range batches {
		if budget <= res.Sent {
			break // the rest stays claimed for the next drain
		}
		r, err := s.drainBatch(ctx, sink, path, budget-res.Sent)
		res.Sent += r.Sent
		res.Skipped += r.Skipped
		if err != nil {
			return res, err
		}
	}
	return res, nil
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

// drainBatch replays one claimed file, at most budget records of it. The file
// is rewritten with whatever was not sent — a sink failure or the budget —
// and removed once nothing replayable remains.
func (s *Spool) drainBatch(ctx context.Context, sink Sink, path string, budget int) (Result, error) {
	entries, skipped, err := s.load(path)
	res := Result{Skipped: skipped}
	if err != nil {
		return res, err
	}
	if len(entries) == 0 {
		return res, remove(path)
	}
	toSend := entries
	if len(toSend) > budget {
		toSend = toSend[:budget]
	}
	for res.Sent < len(toSend) {
		chunk := toSend[res.Sent:]
		if len(chunk) > replayChunk {
			chunk = chunk[:replayChunk]
		}
		n, err := sendChunk(ctx, sink, chunk)
		res.Sent += n
		if err != nil {
			if rewriteErr := securefile.WriteAtomic(path, encode(entries[res.Sent:]), 0o600); rewriteErr != nil {
				return res, fmt.Errorf("flush stopped after %d: %w (and re-queueing the remainder failed: %v)", res.Sent, err, rewriteErr)
			}
			return res, fmt.Errorf("flush stopped after %d of %d: %w", res.Sent, len(entries), err)
		}
	}
	if res.Sent < len(entries) {
		// The budget stopped this call; the remainder waits under the claim
		// name, ahead of newer records, exactly like a mid-flush failure.
		return res, securefile.WriteAtomic(path, encode(entries[res.Sent:]), 0o600)
	}
	return res, remove(path)
}

// sendChunk lands one chunk, in a single round trip when the sink can, and
// reports how many records the sink accepted before any error.
func sendChunk(ctx context.Context, sink Sink, chunk []store.AccessEntry) (int, error) {
	if bs, ok := sink.(BatchSink); ok && len(chunk) > 1 {
		if err := bs.LogAccessBatch(ctx, chunk); err != nil {
			return 0, err // all-or-nothing: see BatchSink
		}
		return len(chunk), nil
	}
	for i, e := range chunk {
		if err := sink.LogAccess(ctx, e); err != nil {
			return i, err
		}
	}
	return len(chunk), nil
}

// load parses one spool file. A line this binary cannot read — truncated by a
// crash mid-append, or stamped with a version it does not know — is counted
// and skipped rather than failing the whole flush: losing one record beats
// losing every record behind it, and the count is how the loss stays visible.
func (s *Spool) load(path string) (entries []store.AccessEntry, skipped int, err error) {
	if s == nil || path == "" {
		return nil, 0, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		e, ok := decodeLine(line)
		if !ok {
			skipped++
			continue
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return entries, skipped, err
	}
	return entries, skipped, nil
}

// encode renders entries back to JSONL, in the current spool format whatever
// format they were read in.
func encode(entries []store.AccessEntry) []byte {
	var buf []byte
	for _, e := range entries {
		line, err := json.Marshal(toLine(e))
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
