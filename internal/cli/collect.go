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
	// Anything still held is not going to get its session now; write it under
	// whichever mode is in force so a clean stop does not silently drop it.
	rest := held.drain()
	if len(rest) == 0 {
		return
	}
	var (
		n   int
		err error
	)
	if requireSession {
		// Held events with no session by now are host churn nobody will attribute
		// (the same events the grace path drops); the attributed insert stores the
		// ones that did get a session and skips the rest by design.
		n, _, err = st.InsertKernelEventsAttributed(ctx, rest)
	} else {
		n, err = st.InsertKernelEvents(ctx, rest)
	}
	*total += n
	if err != nil {
		ui.Warnf(os.Stderr, "final drain on shutdown failed: %v", err)
	}
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
	_, adb, err := env.Audit()
	if err != nil {
		return err
	}
	return adb.Ingesting(cmd.Context(), func(st audit.Ingestor) error {
		ctx := cmd.Context()
		var r io.Reader = os.Stdin
		if opts.from != "" {
			f, err := os.Open(opts.from)
			if err != nil {
				return err
			}
			defer f.Close()
			r = f
		}

		// Scan lines in a goroutine so we can flush on a timer too — a live
		// `tetra getevents` stream never hits EOF, and on a quiet host events
		// would otherwise sit in the buffer until a full batch accumulates.
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

		buf := make([]store.KernelEvent, 0, opts.batch)
		total, skipped := 0, 0
		held := newAttributionHold(opts.grace, opts.batch)
		// flush writes the buffered batch (plus anything still held from
		// earlier flushes). A write that fails must not throw the batch
		// away: everything is re-held so the next flush retries it, bounded
		// by the same cap and grace as an unattributed event. ctx is a
		// parameter so the shutdown path can pass one that is not already
		// cancelled.
		flush := func(ctx context.Context) error {
			pending := held.merge(buf)
			buf = buf[:0]
			if len(pending) == 0 {
				return nil
			}
			var (
				n      int
				missed []int
				err    error
			)
			if opts.requireSession {
				n, missed, err = st.InsertKernelEventsAttributed(ctx, pending)
			} else {
				n, err = st.InsertKernelEvents(ctx, pending)
			}
			total += n
			if err != nil {
				// The write failed — retry the whole batch on the next flush
				// rather than dropping events the operator was told are captured.
				held.holdAll(pending)
				return err
			}
			held.hold(pending, missed)
			return nil
		}

		ticker := time.NewTicker(opts.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// ctx is already cancelled (SIGTERM); a flush on it would fail
				// instantly and throw the buffer away. Give the final write its
				// own short deadline off a live context so a restart still lands
				// what is buffered.
				finalFlushOnShutdown(flush, held, st, opts.requireSession, &total)
				return ctx.Err()
			case <-ticker.C:
				if err := flush(ctx); err != nil {
					ui.Warnf(os.Stderr, "flush: %v", err)
				}
			case line, ok := <-lines:
				if !ok {
					if err := flush(ctx); err != nil {
						return err
					}
					// Don't report success if the input stream errored (read
					// failure, or a line over the 8MiB buffer) — that would
					// silently mask dropped audit events.
					if scanErr != nil {
						return fmt.Errorf("input scan aborted after %d events: %w", total, scanErr)
					}
					// One last attempt for anything still inside its grace, so a
					// clean shutdown does not throw away events whose session was
					// about to appear.
					if rest := held.drain(); len(rest) > 0 {
						if n, _, err := st.InsertKernelEventsAttributed(ctx, rest); err == nil {
							total += n
						}
					}
					ui.Successf(os.Stderr, "ingested %d kernel events (%d unparsed, %d unattributable)",
						total, skipped, held.Dropped())
					return nil
				}
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var te tetraEvent
				if err := json.Unmarshal([]byte(line), &te); err != nil {
					skipped++
					continue
				}
				ev, ok := mapTetra(te, opts.host, opts.serial)
				if !ok {
					skipped++
					continue
				}
				buf = append(buf, ev)
				if len(buf) >= opts.batch {
					if err := flush(ctx); err != nil {
						ui.Warnf(os.Stderr, "flush: %v", err)
					}
				}
			}
		}
	})
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
