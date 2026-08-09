package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

// The serving half: three routes over a snapshot and a live state.
//
// It takes what it serves as arguments rather than reaching for a store, so the
// page can be exercised with a hand-built topology and no database, no Vault
// token and no gateway. That was the point of pulling it out — every route here
// used to be a closure over locals in one RunE, reachable only by running the
// real command against the real fleet.
//
// done ends the event stream when the poller stops. Without it a browser left
// open after Ctrl-C holds a handler that ticks forever against a state nothing
// is updating, and the process does not exit.
func dashboardMux(snap *dashboardSnapshot, live *wireguard.State, interval time.Duration, done <-chan struct{}) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(wgServeHTML)
	})
	mux.HandleFunc("/topology", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(snap.Topo)
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
		// The first frame goes out before the first tick. A page that had to
		// wait one interval for anything to appear read as a page that had
		// failed to load.
		for {
			fmt.Fprintf(w, "data: %s\n\n", live.SnapshotJSON())
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-done:
				return
			case <-tick.C:
			}
		}
	})
	return mux
}
