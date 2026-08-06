package wireguard

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// PeerSample is one peer's counters as a poller read them off the wire.
//
// Its own type rather than the CLI's parsed row: what a poll produced is a fact
// about the overlay, and the shape a particular parser happens to hand back is
// not. The caller converts, which is one small function against having this
// package know how `wg show` formats its output.
type PeerSample struct {
	Iface      string
	PubKey     string
	Endpoint   string
	AllowedIPs []string
	Rx, Tx     int64
	Handshake  int64
}

// Sample is one reading, kept so the next one can be turned into a rate.
type Sample struct {
	Rx, Tx int64
	HS     *time.Time
	At     time.Time
}

func ComputeRate(prev, cur Sample) (rxps, txps float64) {
	dt := cur.At.Sub(prev.At).Seconds()
	if dt <= 0 {
		return 0, 0
	}
	drx, dtx := cur.Rx-prev.Rx, cur.Tx-prev.Tx
	if drx < 0 {
		drx = 0 // counter reset (iface/peer re-created)
	}
	if dtx < 0 {
		dtx = 0
	}
	return float64(drx) / dt, float64(dtx) / dt
}

// --- live state shared between pollers and SSE clients ---

type State struct {
	mu    sync.Mutex
	prev  map[TunnelKey]Sample
	stats map[string]EdgeStat // edge ID -> latest
	errs  map[string]string   // gateway -> poll error

	// drifted holds peers the pollers see on the wire that the snapshot does not
	// contain.
	//
	// record used to drop these — "peer appeared after topology snapshot; ignore
	// until re-serve". The graph is drawn from the database, so a peer added
	// after the last `vctl wg sync` is invisible until someone restarts the
	// server, and nothing says it is there. With the fleet's snapshot six days
	// old, that is a long time to be blind to new tunnels.
	//
	// This does not add them to the graph. The layout is computed from the
	// snapshot, and re-deriving it every poll would move the diagram under the
	// reader's cursor for something that is really a prompt to re-sync. What it
	// does is stop the omission from being silent.
	drifted map[TunnelKey]DriftPeer
}

// DriftPeer is a live-observed peer with no row behind it.
type DriftPeer struct {
	Host       string   `json:"host"`
	Iface      string   `json:"iface"`
	PubKey     string   `json:"pub"`
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed,omitempty"`
	FirstSeen  int64    `json:"firstSeen"`
}

func NewState() *State {
	return &State{
		prev:    map[TunnelKey]Sample{},
		stats:   map[string]EdgeStat{},
		errs:    map[string]string{},
		drifted: map[TunnelKey]DriftPeer{},
	}
}

func (s *State) Record(host string, peers []PeerSample, at time.Time, edgeFor map[TunnelKey]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.errs, host)
	for _, p := range peers {
		k := TunnelKey{host, p.Iface, p.PubKey}
		id, ok := edgeFor[k]
		if !ok {
			// On the wire but not in the snapshot: a peer added since the last
			// `vctl wg sync`. It cannot be placed in a layout derived from the
			// snapshot, so it is reported rather than drawn — and reported rather
			// than dropped, which is what used to happen.
			if _, seen := s.drifted[k]; !seen {
				s.drifted[k] = DriftPeer{
					Host: host, Iface: p.Iface, PubKey: p.PubKey,
					Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs,
					FirstSeen: at.Unix(),
				}
			}
			continue
		}
		// It is in the snapshot after all — drop any earlier drift entry, so a
		// re-sync during a running session clears the notice instead of leaving
		// it to accumulate.
		delete(s.drifted, k)
		var hs *time.Time
		if p.Handshake > 0 {
			t := time.Unix(p.Handshake, 0)
			hs = &t
		}
		cur := Sample{Rx: p.Rx, Tx: p.Tx, HS: hs, At: at}
		side := EdgeSideStat{HS: -1, At: at.Unix()}
		if hs != nil {
			side.HS = int64(time.Since(*hs).Seconds())
		}
		if old, ok := s.prev[k]; ok {
			side.RxPS, side.TxPS = ComputeRate(old, cur)
		}
		s.prev[k] = cur

		// Merge into the tunnel rather than replacing it. Both gateways poll the
		// same tunnel and report counters from their own perspective, so a plain
		// assignment let whichever polled later erase the other end — and since
		// A's tx is B's rx, the drawn direction flipped with poll timing rather
		// than with traffic.
		st := s.stats[id]
		if st.Sides == nil {
			st.Sides = map[string]EdgeSideStat{}
		}
		st.Sides[host] = side
		st.RxPS, st.TxPS, st.HS = flattenSides(st.Sides)
		s.stats[id] = st
	}
}

// flattenSides reduces both ends to the single rx/tx/handshake the page draws.
//
// Rates take the larger of the two sides. The ends measure the same bytes from
// opposite directions and neither is more correct, but a side that has not been
// polled yet reports zero, and taking that would show an idle tunnel as dead.
//
// Handshake takes the smaller — the most recent. A handshake is a property of
// the tunnel, not of the observer, so the fresher observation is simply the
// better-informed one. -1 means never, which loses to any real value.
func flattenSides(sides map[string]EdgeSideStat) (rx, tx float64, hs int64) {
	hs = -1
	for _, s := range sides {
		rx = max(rx, s.RxPS)
		tx = max(tx, s.TxPS)
		if s.HS >= 0 && (hs < 0 || s.HS < hs) {
			hs = s.HS
		}
	}
	return rx, tx, hs
}

func (s *State) Fail(host string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs[host] = err.Error()
}

// snapshotJSON renders the current stats/errors/drift as one SSE payload.
func (s *State) SnapshotJSON() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload := map[string]any{"edges": s.stats, "errors": s.errs, "at": time.Now().Unix()}
	if len(s.drifted) > 0 {
		payload["drift"] = s.DriftList()
	}
	b, _ := json.Marshal(payload)
	return b
}

// driftList returns the drifted peers in a stable order. Callers hold the lock.
//
// Sorted because this ends up in a list on screen: an unstable order would make
// the panel reshuffle every two seconds and read as churn rather than as a fixed
// set of things to go fix.
func (s *State) DriftList() []DriftPeer {
	out := make([]DriftPeer, 0, len(s.drifted))
	for _, p := range s.drifted {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Iface != out[j].Iface {
			return out[i].Iface < out[j].Iface
		}
		return out[i].PubKey < out[j].PubKey
	})
	return out
}
