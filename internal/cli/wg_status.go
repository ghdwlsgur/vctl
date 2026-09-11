package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// wgStatusCmd and wgDownCmd manage the tunnel this machine is running. Both
// are local — a state file and a pid — so, like `vctl cache`, they are not
// gated: there is no fleet resource to authorize.

func wgStatusCmd(env cmdkit.Env) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Is the built-in WireGuard tunnel up on this machine, and how is it doing",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := cmdkit.CommandOutput(cmd, asJSON)
			if err != nil {
				return err
			}
			return env.WithApp(func(a *app.App) error {
				st, ok := readTunnelState(tunnelStatePath(a.Cfg.StateDir))
				if format != cmdkit.OutputTable {
					if !ok {
						return cmdkit.WriteStructured(format, nil)
					}
					return cmdkit.WriteStructured(format, st)
				}
				if !ok {
					ui.Infof(os.Stdout, "no tunnel is running — `vctl wg connect` (terminal) or `vctl wg connect --background`; kubectl through `vctl k8s use` starts one on demand")
					return nil
				}
				printTunnelState(st)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "the state as JSON (null when none)")
	return cmdkit.SupportsStructuredOutput(cmd)
}

func printTunnelState(st tunnelState) {
	mode := "terminal"
	if st.Background {
		mode = "background"
	}
	hs := "none yet"
	if !st.LastHandshake.IsZero() {
		hs = time.Since(st.LastHandshake).Round(time.Second).String() + " ago"
	}
	idle := st.IdleExit
	if idle == "" {
		idle = "never"
	}
	ui.Successf(os.Stdout, "tunnel up (%s, pid %d) since %s", mode, st.PID, st.StartedAt.Format("15:04:05"))
	rows := [][]string{
		{"address", st.Address},
		{"gateway", fmt.Sprintf("%s (%s)", st.Gateway, st.Endpoint)},
		{"socks5", ui.OrDash(st.Socks)},
		{"handshake", hs},
		{"traffic", fmt.Sprintf("rx %s · tx %s", humanBytes(int64(st.RxBytes)), humanBytes(int64(st.TxBytes)))},
		{"clients", fmt.Sprintf("%d open · idles out after %s", st.OpenConns, idle)},
		{"log", ui.OrDash(st.Log)},
	}
	for _, r := range rows {
		fmt.Fprintf(os.Stdout, "  %-10s %s\n", r[0], r[1])
	}
	if time.Since(st.UpdatedAt) > 30*time.Second {
		ui.Warnf(os.Stdout, "state last refreshed %s ago — the process is alive but may be stuck", time.Since(st.UpdatedAt).Round(time.Second))
	}
}

func wgDownCmd(env cmdkit.Env) *cobra.Command {
	return &cobra.Command{
		Use:     "down",
		Aliases: []string{"disconnect"},
		Short:   "Stop the tunnel running on this machine",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return env.WithApp(func(a *app.App) error {
				path := tunnelStatePath(a.Cfg.StateDir)
				st, ok := readTunnelState(path)
				if !ok {
					_ = os.Remove(path)
					ui.Infof(os.Stdout, "no tunnel is running")
					return nil
				}
				if err := terminateProcess(st.PID); err != nil {
					return fmt.Errorf("stop pid %d: %w", st.PID, err)
				}
				for i := 0; i < 50 && processAlive(st.PID); i++ {
					time.Sleep(100 * time.Millisecond)
				}
				if processAlive(st.PID) {
					return fmt.Errorf("pid %d did not exit within 5s", st.PID)
				}
				_ = os.Remove(path)
				ui.Successf(os.Stdout, "tunnel down (pid %d, was up %s)", st.PID, time.Since(st.StartedAt).Round(time.Second))
				return nil
			})
		},
	}
}
