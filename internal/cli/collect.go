package cli

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// Tetragon JSON event subset (from `tetra getevents -o json`). Only the fields
// needed for the SRE action timeline; unknown fields are ignored.
type tetraProcess struct {
	PID       int    `json:"pid"`
	UID       int    `json:"uid"`
	CWD       string `json:"cwd"`
	Binary    string `json:"binary"`
	Arguments string `json:"arguments"`
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

func collectCmd() *cobra.Command {
	var (
		from   string
		host   string
		serial string
		batch  int
	)
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Ingest Tetragon kernel events into the central audit store",
		Long: `collect reads Tetragon JSON events (one per line) and writes them to the
central kernel_event table, where vctl session can join them with access logs.

Typical host wiring (systemd or sidecar):
  tetra getevents -o json | vctl collect

Events link to a session by cgroup when the login stamper recorded one; pass
--serial to attach a known access explicitly.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, true) // RW: kernel_event insert
			if err != nil {
				return err
			}
			defer st.Close()

			var r io.Reader = os.Stdin
			if from != "" {
				f, err := os.Open(from)
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}

			sc := bufio.NewScanner(r)
			sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
			buf := make([]store.KernelEvent, 0, batch)
			total, skipped := 0, 0

			flush := func() error {
				if len(buf) == 0 {
					return nil
				}
				n, err := st.InsertKernelEvents(ctx, buf)
				total += n
				buf = buf[:0]
				return err
			}

			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				var te tetraEvent
				if err := json.Unmarshal([]byte(line), &te); err != nil {
					skipped++
					continue
				}
				ev, ok := mapTetra(te, host, serial)
				if !ok {
					skipped++
					continue
				}
				buf = append(buf, ev)
				if len(buf) >= batch {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			if err := sc.Err(); err != nil {
				return err
			}
			if err := flush(); err != nil {
				return err
			}
			ui.Successf(os.Stderr, "ingested %d kernel events (%d skipped)", total, skipped)
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "read events from a file instead of stdin")
	cmd.Flags().StringVar(&host, "host", "", "override hostname (default: event node_name)")
	cmd.Flags().StringVar(&serial, "serial", "", "attach events to a known cert serial")
	cmd.Flags().IntVar(&batch, "batch", 200, "insert batch size")
	return cmd
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
			Args: p.Arguments, CWD: p.CWD, UID: p.UID,
		}, host != "" && p.Binary != ""
	case te.ProcessExit != nil:
		p := te.ProcessExit.Process
		code := te.ProcessExit.Status
		return store.KernelEvent{
			CertSerial: serial, Hostname: host, TS: ts, Kind: "exit",
			PID: p.PID, Binary: p.Binary, UID: p.UID, ExitCode: &code,
		}, host != ""
	default:
		return store.KernelEvent{}, false
	}
}
