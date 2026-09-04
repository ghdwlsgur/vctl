package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/audit"
	"github.com/ghdwlsgur/vctl/internal/auditredact"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// shutdownFlushTimeout bounds the final write when the process is asked to stop.
// The signal context is already cancelled by then, so the last flush and drain
// run on a fresh context with this deadline — long enough for one batch insert,
// short enough not to hold up a restart.
const shutdownFlushTimeout = 5 * time.Second

// finalFlushOnShutdown makes one bounded attempt to write what is still buffered
// and held when the collector is stopping. Without it the shutdown flush ran on
// the already-cancelled signal context, failed instantly, and every restart lost
// up to a full batch plus everything inside its attribution grace.
func finalFlushOnShutdown(
	flush func(context.Context) error,
	held *attributionHold,
	st audit.Ingestor,
	requireSession bool,
	total *int,
) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownFlushTimeout)
	defer cancel()
	if err := flush(ctx); err != nil {
		ui.Warnf(os.Stderr, "final flush on shutdown: %v", err)
	}
	n, err := drainHeld(ctx, held, st, requireSession)
	*total += n
	if err != nil {
		ui.Warnf(os.Stderr, "final drain on shutdown failed: %v", err)
	}
}

// drainHeld writes whatever is still inside its attribution grace when the
// collector stops — under whichever mode is in force, so a clean stop does
// not silently drop events the operator was told are captured. Held events
// with no session by now are host churn nobody will attribute: with
// --require-session the attributed insert stores the ones that did get a
// session and skips the rest by design; without it everything is stored.
//
// Both stop paths (signal and end of input) go through here. The end-of-input
// path once used the attributed insert regardless of the mode, so with
// --require-session=false a batch re-held after a failed write was skipped at
// EOF while the signal path would have stored it.
func drainHeld(ctx context.Context, held *attributionHold, st audit.Ingestor, requireSession bool) (int, error) {
	rest := held.drain()
	if len(rest) == 0 {
		return 0, nil
	}
	if requireSession {
		n, _, err := st.InsertKernelEventsAttributed(ctx, rest)
		return n, err
	}
	return st.InsertKernelEvents(ctx, rest)
}

// Tetragon JSON event subset (from `tetra getevents -o json`). Only the fields
// needed for the SRE action timeline; unknown fields are ignored.
type tetraProcess struct {
	PID       int    `json:"pid"`
	UID       int    `json:"uid"`
	CWD       string `json:"cwd"`
	Binary    string `json:"binary"`
	Arguments string `json:"arguments"`
	// protojson renders uint64 as a string; parsed best-effort. Lets kernel
	// events link to a session by cgroup so concurrent sessions don't mix.
	CgroupID string `json:"cgroup_id"`
}

func (p tetraProcess) cgroup() int64 {
	n, _ := strconv.ParseInt(p.CgroupID, 10, 64)
	return n
}

type tetraExec struct {
	Process tetraProcess `json:"process"`
	Parent  tetraProcess `json:"parent"`
}

type tetraExit struct {
	Process tetraProcess `json:"process"`
	Status  int          `json:"status"`
}

type tetraEvent struct {
	NodeName    string     `json:"node_name"`
	Time        time.Time  `json:"time"`
	ProcessExec *tetraExec `json:"process_exec"`
	ProcessExit *tetraExit `json:"process_exit"`
}

func collectCmd(env cmdkit.Env) *cobra.Command {
	var opts collectOptions
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Ingest Tetragon kernel events into the central audit store",
		Long: `collect reads Tetragon JSON events (one per line) and writes them to the
central kernel_event table, where vctl session can join them with access logs.

Typical host wiring (systemd or sidecar):
  tetra getevents -o json | vctl collect

Events link to a session by cgroup when the login stamper recorded one; pass
--serial to attach a known access explicitly.

By default only events that link to a session are stored. A host emits exec/exit
for everything it runs — on a Kubernetes node that is overwhelmingly container and
kubelet churn, which belongs to no login and which no later row can attribute, so
storing it buys nothing and costs everything. A miss is held for
--attribution-grace and retried first, because a login's earliest commands arrive
before watch-sessions has written the session row. Pass --require-session=false
for full host capture.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCollect(cmd, env, opts)
		},
	}
	cmd.Flags().StringVar(&opts.from, "from", "", "read events from a file instead of stdin")
	cmd.Flags().StringVar(&opts.host, "host", "", "inventory hostname to record events under (default: event node_name); must match what watch-sessions records or nothing attributes")
	cmdkit.RegisterCompletion(cmd, "host", cmdkit.CompleteInventoryHost(env))
	cmd.Flags().StringVar(&opts.serial, "serial", "", "attach events to a known cert serial")
	cmd.Flags().IntVar(&opts.batch, "batch", 200, "insert batch size")
	cmd.Flags().DurationVar(&opts.flushInterval, "flush-interval", 3*time.Second, "max time before flushing buffered events")
	cmd.Flags().BoolVar(&opts.requireSession, "require-session", true, "store only events that link to a session; false captures all host activity")
	cmd.Flags().DurationVar(&opts.grace, "attribution-grace", 30*time.Second, "how long to hold an unlinked event waiting for its session row")
	return cmd
}

type collectOptions struct {
	from           string
	host           string
	serial         string
	batch          int
	flushInterval  time.Duration
	requireSession bool
	grace          time.Duration
}

func runCollect(cmd *cobra.Command, env cmdkit.Env, opts collectOptions) error {
	// Before touching the database: a non-positive batch made make() panic on a
	// negative and flushed on every event at zero. The hold sizes itself from
	// the same number, so one refusal here covers both.
	if opts.batch <= 0 {
		return fmt.Errorf("--batch must be > 0 (got %d)", opts.batch)
	}
	_, adb, err := env.Audit()
	if err != nil {
		return err
	}
	ctx := cmd.Context()
	return adb.Ingesting(ctx, func(st audit.Ingestor) error {
		r, closeInput, err := openCollectInput(opts)
		if err != nil {
			return err
		}
		defer closeInput()

		lines, scanErr := scanLines(r)
		c := newCollector(st, opts)

		ticker := time.NewTicker(opts.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// ctx is already cancelled (SIGTERM); a flush on it would fail
				// instantly and throw the buffer away. Give the final write its
				// own short deadline off a live context so a restart still lands
				// what is buffered.
				finalFlushOnShutdown(c.flush, c.held, c.st, c.opts.requireSession, &c.total)
				return ctx.Err()
			case <-ticker.C:
				if err := c.flush(ctx); err != nil {
					ui.Warnf(os.Stderr, "flush: %v", err)
				}
			case line, ok := <-lines:
				if !ok {
					return c.finish(ctx, scanErr)
				}
				c.ingest(ctx, line)
			}
		}
	})
}

// openCollectInput is the event source: the --from file when one was given,
// otherwise stdin. The returned func releases it; stdin has nothing to release.
func openCollectInput(opts collectOptions) (io.Reader, func(), error) {
	if opts.from == "" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(opts.from)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// scanLines hands the input over a line at a time. It scans in a goroutine so
// the caller can flush on a timer too — a live `tetra getevents` stream never
// hits EOF, and on a quiet host events would otherwise sit in the buffer until
// a full batch accumulates. The returned func reports the scan error; read it
// only after lines closes (close happens-after the assignment).
func scanLines(r io.Reader) (<-chan string, func() error) {
	lines := make(chan string, 4096)
	var scanErr error // read after lines closes (close happens-after assignment)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
		for sc.Scan() {
			lines <- sc.Text()
		}
		scanErr = sc.Err()
		close(lines)
	}()
	return lines, func() error { return scanErr }
}

// collector is the batch between the input and the store: the events read since
// the last flush, the ones still inside their attribution grace, and the counts
// the final summary reports.
type collector struct {
	st   audit.Ingestor
	opts collectOptions

	buf     []store.KernelEvent
	held    *attributionHold
	total   int
	skipped int
}

func newCollector(st audit.Ingestor, opts collectOptions) *collector {
	return &collector{
		st:   st,
		opts: opts,
		buf:  make([]store.KernelEvent, 0, opts.batch),
		held: newAttributionHold(opts.grace, opts.batch),
	}
}

// flush writes the buffered batch (plus anything still held from earlier
// flushes). A write that fails must not throw the batch away: everything is
// re-held so the next flush retries it, bounded by the same cap and grace as an
// unattributed event. ctx is a parameter so the shutdown path can pass one that
// is not already cancelled.
func (c *collector) flush(ctx context.Context) error {
	pending := c.held.merge(c.buf)
	c.buf = c.buf[:0]
	if len(pending) == 0 {
		return nil
	}
	var (
		n      int
		missed []int
		err    error
	)
	if c.opts.requireSession {
		n, missed, err = c.st.InsertKernelEventsAttributed(ctx, pending)
	} else {
		n, err = c.st.InsertKernelEvents(ctx, pending)
	}
	c.total += n
	if err != nil {
		// The write failed — retry the whole batch on the next flush
		// rather than dropping events the operator was told are captured.
		c.held.holdAll(pending)
		return err
	}
	c.held.hold(pending, missed)
	return nil
}

// ingest parses one Tetragon line into the batch and flushes once the batch is
// full. A blank, unparsable or unmappable line counts as skipped.
func (c *collector) ingest(ctx context.Context, line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	var te tetraEvent
	if err := json.Unmarshal([]byte(line), &te); err != nil {
		c.skipped++
		return
	}
	ev, ok := mapTetra(te, c.opts.host, c.opts.serial)
	if !ok {
		c.skipped++
		return
	}
	c.buf = append(c.buf, ev)
	if len(c.buf) >= c.opts.batch {
		if err := c.flush(ctx); err != nil {
			ui.Warnf(os.Stderr, "flush: %v", err)
		}
	}
}

// finish is the end-of-input stop path: the last flush, the verdict on the
// input, whatever is still held, then the summary. scanErr is the scanner's
// report, safe to read here because lines has closed.
func (c *collector) finish(ctx context.Context, scanErr func() error) error {
	if err := c.flush(ctx); err != nil {
		return err
	}
	// Don't report success if the input stream errored (read failure, or a
	// line over the 8MiB buffer) — that would silently mask dropped audit
	// events.
	if err := scanErr(); err != nil {
		return fmt.Errorf("input scan aborted after %d events: %w", c.total, err)
	}
	// One last attempt for anything still inside its grace, so a clean
	// shutdown does not throw away events whose session was about to appear.
	n, err := drainHeld(ctx, c.held, c.st, c.opts.requireSession)
	c.total += n
	if err != nil {
		ui.Warnf(os.Stderr, "final drain at end of input failed: %v", err)
	}
	ui.Successf(os.Stderr, "ingested %d kernel events (%d unparsed, %d unattributable)",
		c.total, c.skipped, c.held.Dropped())
	return nil
}

func mapTetra(te tetraEvent, hostOverride, serial string) (store.KernelEvent, bool) {
	host := hostOverride
	if host == "" {
		host = te.NodeName
	}
	ts := te.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	switch {
	case te.ProcessExec != nil:
		p := te.ProcessExec.Process
		return store.KernelEvent{
			CertSerial: serial, Hostname: host, TS: ts, Kind: "exec",
			PID: p.PID, PPID: te.ProcessExec.Parent.PID, Binary: p.Binary,
			Args: auditredact.Arguments(p.Arguments), CWD: p.CWD, UID: p.UID, CgroupID: p.cgroup(),
		}, host != "" && p.Binary != ""
	case te.ProcessExit != nil:
		p := te.ProcessExit.Process
		code := te.ProcessExit.Status
		return store.KernelEvent{
			CertSerial: serial, Hostname: host, TS: ts, Kind: "exit",
			PID: p.PID, Binary: p.Binary, UID: p.UID, ExitCode: &code, CgroupID: p.cgroup(),
		}, host != ""
	default:
		return store.KernelEvent{}, false
	}
}
