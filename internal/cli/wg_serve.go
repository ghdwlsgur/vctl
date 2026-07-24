package cli

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

//go:embed wg_serve.html
var wgServeHTML []byte

// --- topology (built once from the DB at startup) ---

// wgNode is one vertex in the dashboard graph: a collected gateway interface's
// host, or an external (uncollected) peer endpoint.
type wgNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"` // gateway | external
}

// wgEdge is one tunnel: a peer entry, resolved to the far-end gateway when both
// ends were collected.
type wgEdge struct {
	ID      string `json:"id"`
	Source  string `json:"source"`
	Target  string `json:"target"`
	Iface   string `json:"iface"`
	Allowed string `json:"allowed"`
}

type wgTopology struct {
	Nodes []wgNode `json:"nodes"`
	Edges []wgEdge `json:"edges"`
}

// edgeStat is the live per-tunnel measurement pushed to browsers.
type edgeStat struct {
	RxPS float64 `json:"rx"` // bytes/sec toward the source gateway
	TxPS float64 `json:"tx"` // bytes/sec away from the source gateway
	HS   int64   `json:"hs"` // seconds since last handshake, -1 = never
}

// buildWGTopology turns the collected interfaces/peers into a node/edge graph.
// Peers whose public key matches another collected interface become a single
// gateway↔gateway edge (canonical side = lexically smaller host); the rest hang
// off their gateway as external nodes. It also returns the sample→edge mapping
// the pollers use to attribute live rates.
func buildWGTopology(ifaces []store.WGInterfaceRow, peers []store.WGPeerRow) (wgTopology, map[tunnelKey]string) {
	idx := pubIndex(ifaces)

	var topo wgTopology
	nodeSeen := map[string]bool{}
	addNode := func(n wgNode) {
		if !nodeSeen[n.ID] {
			nodeSeen[n.ID] = true
			topo.Nodes = append(topo.Nodes, n)
		}
	}
	for _, i := range ifaces {
		addNode(wgNode{ID: i.Host, Label: i.Host, Kind: "gateway"})
	}

	edgeFor := map[tunnelKey]string{}
	edgeSeen := map[string]bool{}
	sorted := append([]store.WGPeerRow{}, peers...)
	sort.Slice(sorted, func(a, b int) bool {
		if sorted[a].Host != sorted[b].Host {
			return sorted[a].Host < sorted[b].Host
		}
		if sorted[a].Iface != sorted[b].Iface {
			return sorted[a].Iface < sorted[b].Iface
		}
		return sorted[a].PeerPubKey < sorted[b].PeerPubKey
	})
	for _, p := range sorted {
		k := tunnelKey{p.Host, p.Iface, p.PeerPubKey}
		if far, ok := idx[p.PeerPubKey]; ok {
			// Resolved gateway↔gateway tunnel: one edge, canonical side first.
			a, b := p.Host, far.host
			if a > b {
				a, b = b, a
			}
			id := "gw|" + a + "|" + b + "|" + p.Iface
			edgeFor[k] = id
			if edgeSeen[id] {
				continue
			}
			edgeSeen[id] = true
			topo.Edges = append(topo.Edges, wgEdge{
				ID: id, Source: p.Host, Target: far.host,
				Iface: p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
			})
			continue
		}
		extID := "ext|" + shortKey(p.PeerPubKey)
		label := p.Endpoint
		if label == "" {
			label = shortKey(p.PeerPubKey)
		}
		addNode(wgNode{ID: extID, Label: label, Kind: "external"})
		id := p.Host + "|" + p.Iface + "|" + shortKey(p.PeerPubKey)
		edgeFor[k] = id
		topo.Edges = append(topo.Edges, wgEdge{
			ID: id, Source: p.Host, Target: extID,
			Iface: p.Iface, Allowed: strings.Join(p.AllowedIPs, ", "),
		})
	}
	return topo, edgeFor
}

// --- live state shared between pollers and SSE clients ---

type wgServeState struct {
	mu    sync.Mutex
	prev  map[tunnelKey]wgSample
	stats map[string]edgeStat // edge ID -> latest
	errs  map[string]string   // gateway -> poll error
}

func newWGServeState() *wgServeState {
	return &wgServeState{prev: map[tunnelKey]wgSample{}, stats: map[string]edgeStat{}, errs: map[string]string{}}
}

func (s *wgServeState) record(host string, peers []wgParsedPeer, at time.Time, edgeFor map[tunnelKey]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.errs, host)
	for _, p := range peers {
		k := tunnelKey{host, p.Iface, p.PubKey}
		id, ok := edgeFor[k]
		if !ok {
			continue // peer appeared after topology snapshot; ignore until re-serve
		}
		var hs *time.Time
		if p.Handshake > 0 {
			t := time.Unix(p.Handshake, 0)
			hs = &t
		}
		cur := wgSample{rx: p.Rx, tx: p.Tx, hs: hs, at: at}
		st := edgeStat{HS: -1}
		if hs != nil {
			st.HS = int64(time.Since(*hs).Seconds())
		}
		if old, ok := s.prev[k]; ok {
			st.RxPS, st.TxPS = computeRate(old, cur)
		}
		s.prev[k] = cur
		s.stats[id] = st
	}
}

func (s *wgServeState) fail(host string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs[host] = err.Error()
}

// snapshotJSON renders the current stats/errors as one SSE payload.
func (s *wgServeState) snapshotJSON() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"edges": s.stats, "errors": s.errs, "at": time.Now().Unix()})
	return b
}

// --- command ---

func wgServeCmd() *cobra.Command {
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
			a, err := newApp()
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
			topo, edgeFor := buildWGTopology(ifaces, peers)

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

			conn := newConnector(a)
			state := newWGServeState()
			interval := time.Duration(intervalSec) * time.Second
			timeout := time.Duration(timeoutSec) * time.Second

			pollCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			for _, t := range targets {
				go func(t monTarget) {
					for {
						res, err := conn.Execute(pollCtx, access.Request{Target: t.tgt, HostKey: access.HostKeyAcceptNew}, wgDumpCmd, timeout)
						if err != nil {
							state.fail(t.name, err)
						} else {
							_, ps := parseWGDump(res.Stdout)
							state.record(t.name, ps, time.Now(), edgeFor)
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
					fmt.Fprintf(w, "data: %s\n\n", state.snapshotJSON())
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
