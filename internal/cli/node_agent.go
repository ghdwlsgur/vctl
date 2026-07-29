package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/hoststatus"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func nodeAgentCmd() *cobra.Command {
	var (
		hostname string
		interval time.Duration
		once     bool
	)
	cmd := &cobra.Command{
		Use:   "node-agent",
		Short: "Report lightweight host runtime status",
		Long: `node-agent reports observed host state to server_status.

It never creates inventory. The host must already exist in the servers table;
otherwise the heartbeat is ignored. Use AppRole credentials and a narrow
database role for low-risk, low-resource status reporting.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := newApp()
			if err != nil {
				return err
			}

			if hostname == "" {
				hostname, _ = os.Hostname()
			}
			if hostname == "" {
				return fmt.Errorf("hostname is required")
			}

			conn := &statusConn{open: func() (statusSink, error) {
				return a.OpenStore(ctx, app.PurposeStatus)
			}}
			defer conn.close()

			report := func() error { return conn.report(ctx, hostname) }
			return runPeriodic(ctx, once, false, interval, 5*time.Minute, report, func(err error) {
				ui.Warnf(os.Stderr, "status report failed: %v", err)
			})
		},
	}
	cmd.Flags().StringVar(&hostname, "hostname", "", "inventory hostname to report; defaults to os hostname")
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Minute, "heartbeat interval")
	cmd.Flags().BoolVar(&once, "once", false, "report once and exit")
	return cmd
}

// statusConn holds the agent's database handle across heartbeats and reopens it
// after a failure.
//
// The connection is deliberately not established before the loop starts. Opening
// it eagerly made a dependency that was down *at boot* fatal, while the very same
// dependency going down one heartbeat later was only a warning — the agent
// tolerated an outage it had already survived and died on one it had not. The
// boot case is the common one, because whatever takes Vault or Postgres out
// usually reboots hosts too.
//
// Dropping the handle on error matters as much as retrying. Reopening runs the
// full path again: AppRole login, then a fresh dynamic database credential. A
// handle kept across a failure can be one whose lease has already lapsed, and no
// number of retries on it will ever succeed.
// statusSink is the slice of *store.Store the agent actually uses. Keeping it
// this narrow is what makes the reconnect behavior testable without a database.
type statusSink interface {
	UpsertServerStatus(context.Context, store.ServerStatus) (bool, error)
	Close()
}

type statusConn struct {
	open func() (statusSink, error)
	st   statusSink
}

func (c *statusConn) report(ctx context.Context, hostname string) error {
	if c.st == nil {
		st, err := c.open()
		if err != nil {
			return err
		}
		c.st = st
	}
	if err := reportStatus(ctx, c.st, hostname); err != nil {
		c.close()
		return err
	}
	return nil
}

func (c *statusConn) close() {
	if c.st != nil {
		c.st.Close()
		c.st = nil
	}
}

// reportStatus collects host status and upserts it for an already-registered
// host. A heartbeat for an unknown host is ignored (warned), not an error.
func reportStatus(ctx context.Context, st statusSink, hostname string) error {
	status := hoststatus.Collect(hostname, Version)
	ok, err := st.UpsertServerStatus(ctx, status)
	if err != nil {
		return err
	}
	if !ok {
		ui.Warnf(os.Stderr, "status ignored: %s is not registered in inventory", hostname)
		return nil
	}
	ui.Infof(os.Stderr, "reported status for %s", hostname)
	return nil
}
