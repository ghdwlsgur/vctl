package cli

import (
	"context"
	_ "embed"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

//go:embed wg_serve.html
var wgServePage string

//go:embed wg_model.js
var wgModelJS string

//go:embed wg_view.js
var wgViewJS string

// wgServeHTML is the dashboard as served: one document, with both script files
// inlined where their <script src> tags sit in the page.
//
// They are separate files on disk because that is what makes them testable —
// wg_model.js is required directly by Node, which is only possible while it is
// a file rather than a run of text inside a <script> block. The page is still a
// single document because the handler below serves exactly one thing, and
// because the same HTML is opened off disk with a topology spliced in, where a
// second HTTP round trip is not available to it.
var wgServeHTML = inlineDashboardScripts()

// inlineDashboardScripts splices the embedded JS into the embedded page.
//
// A missing tag leaves the page pointing at a file the server does not route,
// so TestDashboardPageInlinesItsScripts asserts the substitution happened rather
// than trusting it.
func inlineDashboardScripts() []byte {
	page := wgServePage
	for _, s := range []struct{ tag, body string }{
		{`<script src="wg_model.js"></script>`, wgModelJS},
		{`<script src="wg_view.js"></script>`, wgViewJS},
	} {
		page = strings.Replace(page, s.tag, "<script>\n"+s.body+"</script>", 1)
	}
	return []byte(page)
}

// --- command ---

func wgServeCmd(env cmdkit.Env) *cobra.Command {
	var (
		addr        string
		intervalSec int
		timeoutSec  int
	)
	cmd := &cobra.Command{
		Use:   "serve [host...]",
		Short: "Web dashboard with live animated traffic flow over the WG topology",
		Long: `serve starts a local web dashboard: the collected WireGuard topology drawn
as a graph, with per-tunnel traffic animated as flowing packets (speed and
density follow live rx/tx rates polled over SSH). The topology comes from the
DB (run 'vctl wg sync' first); rates are read live and never written back.`,
		// Three pieces, wired: what is drawn (wg_dashboard.go), what moves on it
		// (wg_poller.go), and what serves it (wg_dashboard_http.go). What is left
		// here is the part that genuinely belongs to a command — flags, the store
		// it all hangs off, and shutdown.
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.App()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
			if err != nil {
				return err
			}
			defer st.Close()

			warn := func(format string, args ...any) { ui.Warnf(os.Stderr, format, args...) }
			snap, err := loadDashboardSnapshot(ctx, st, warn)
			if err != nil {
				return err
			}

			targets, err := wgPollTargets(ctx, a, st, args, warn)
			if err != nil {
				return err
			}
			interval := time.Duration(intervalSec) * time.Second
			live := newLivePoller(cmdkit.NewConnector(a).Monitor(), targets, snap.EdgeFor,
				interval, time.Duration(timeoutSec)*time.Second)
			stop, done := live.Start(ctx)
			defer stop()

			srv := &http.Server{Addr: addr, Handler: dashboardMux(snap, live.State(), interval, done)}
			go func() {
				<-ctx.Done()
				shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
				defer c()
				srv.Shutdown(shutdownCtx)
			}()
			ui.Successf(os.Stderr, "wg dashboard: http://%s  (%d gateways, every %s; Ctrl-C to stop)",
				displayAddr(addr), live.Gateways(), interval)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8420", "listen address")
	cmd.Flags().IntVar(&intervalSec, "interval", 2, "poll interval (seconds)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 10, "per-poll SSH timeout (seconds)")
	return cmdkit.Gate(cmd, "wg")
}

// displayAddr turns a bind address into a clickable one (":8420" → "127.0.0.1:8420").
func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}
