package cli

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

//go:embed wg_serve.html
var wgServeHTML []byte

// --- command ---

func wgServeCmd(env CommandEnv) *cobra.Command {
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
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			a, err := env.newApp()
			if err != nil {
				return err
			}
			st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
			if err != nil {
				return err
			}
			defer st.Close()

			ifaces, err := st.WGInterfaces(ctx)
			if err != nil {
				return err
			}
			peers, err := st.WGPeers(ctx)
			if err != nil {
				return err
			}
			if len(ifaces) == 0 {
				return fmt.Errorf("no WireGuard data. Run 'vctl wg sync' first.")
			}
			servers, err := st.List(ctx, "")
			if err != nil {
				ui.Warnf(os.Stderr, "list servers for site grouping: %v", err)
			}
			annotations, err := st.WGEndpointAnnotations(ctx)
			if err != nil {
				ui.Warnf(os.Stderr, "list endpoint annotations (run vctl sync --migrate): %v", err)
			}
			topo, edgeFor := wireguard.Build(ifaces, peers, servers, annotations)
			if vips, err := st.IPAllocList(ctx, "dnat-vip", "", ""); err == nil {
				for _, v := range vips {
					note := strings.TrimSpace(strings.TrimSpace(v.OS) + " " + strings.TrimSpace(v.Note))
					topo.Vips = append(topo.Vips, wireguard.Vip{
						IP: v.IP, Label: v.Label, Iface: v.WGTunnel, Note: note,
						Owner: v.OwnerPublicKey,
					})
				}
			}

			hosts, err := wgMonitorHosts(ctx, st, args, false)
			if err != nil {
				return err
			}
			targets := make([]monTarget, 0, len(hosts))
			for i := range hosts {
				tgt, err := access.BuildTarget(ctx, st, &hosts[i], a.Cfg.SSHDirectFirst)
				if err != nil {
					ui.Warnf(os.Stderr, "%s: %v", hosts[i].Hostname, err)
					continue
				}
				targets = append(targets, monTarget{name: hosts[i].Hostname, tgt: tgt})
			}
			if len(targets) == 0 {
				return fmt.Errorf("no reachable gateways to poll")
			}

			// Polling telemetry, not access: Monitor records the first poll per
			// gateway and every change of outcome after that, instead of a row
			// every 2s. See access.Monitor.
			mon := newConnector(a).Monitor()
			state := wireguard.NewState()
			interval := time.Duration(intervalSec) * time.Second
			timeout := time.Duration(timeoutSec) * time.Second

			pollCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			for _, t := range targets {
				go func(t monTarget) {
					for {
						res, err := mon.Poll(pollCtx, access.Request{Target: t.tgt, HostKey: access.HostKeyAcceptNew}, wireguard.DumpCmd, timeout)
						if err != nil {
							state.Fail(t.name, err)
						} else {
							_, ps := wireguard.ParseDump(res.Stdout)
							state.Record(t.name, samples(ps), time.Now(), edgeFor)
						}
						select {
						case <-pollCtx.Done():
							return
						case <-time.After(interval):
						}
					}
				}(t)
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Write(wgServeHTML)
			})
			mux.HandleFunc("/topology", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(topo)
			})
			mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
				fl, ok := w.(http.Flusher)
				if !ok {
					http.Error(w, "streaming unsupported", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				tick := time.NewTicker(interval)
				defer tick.Stop()
				for {
					fmt.Fprintf(w, "data: %s\n\n", state.SnapshotJSON())
					fl.Flush()
					select {
					case <-r.Context().Done():
						return
					case <-pollCtx.Done():
						return
					case <-tick.C:
					}
				}
			})

			srv := &http.Server{Addr: addr, Handler: mux}
			go func() {
				<-ctx.Done()
				shutdownCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
				defer c()
				srv.Shutdown(shutdownCtx)
			}()
			ui.Successf(os.Stderr, "wg dashboard: http://%s  (%d gateways, every %s; Ctrl-C to stop)",
				displayAddr(addr), len(targets), interval)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:8420", "listen address")
	cmd.Flags().IntVar(&intervalSec, "interval", 2, "poll interval (seconds)")
	cmd.Flags().IntVar(&timeoutSec, "timeout", 10, "per-poll SSH timeout (seconds)")
	return gate(cmd, "wg", classRead)
}

// displayAddr turns a bind address into a clickable one (":8420" → "127.0.0.1:8420").
func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	return addr
}
