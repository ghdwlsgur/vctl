package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

// The serving half of `vctl wg serve`, exercised with no database, no Vault
// token, no SSH and no gateway.
//
// None of this was reachable before. Every route was a closure over locals
// inside one RunE, so the only way to find out whether /topology served the
// topology was to run the real command against the real fleet — which is also
// the thing that holds twelve production SSH sessions open. These tests exist
// because the split made them possible, and they are the reason the split was
// worth doing.

func testSnapshot() *dashboardSnapshot {
	return &dashboardSnapshot{
		Topo: wireguard.Topology{
			Nodes:       []wireguard.Node{{ID: "hub", Label: "wireguard-gw"}},
			CollectedAt: time.Unix(1780000000, 0),
		},
		EdgeFor: map[wireguard.TunnelKey]string{},
	}
}

func TestDashboardServesTheTopologyItWasBuiltWith(t *testing.T) {
	mux := dashboardMux(testSnapshot(), wireguard.NewState(), time.Second, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/topology", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/topology = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type = %q, want application/json", ct)
	}
	var got wireguard.Topology
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v\n%s", err, rec.Body.String())
	}
	if len(got.Nodes) != 1 || got.Nodes[0].ID != "hub" {
		t.Errorf("nodes = %+v, want the one it was given", got.Nodes)
	}
	// The staleness banner is drawn from this. A route that dropped it would
	// leave a six-day-old picture reading as current — the failure the field
	// was added for.
	if got.CollectedAt.Unix() != 1780000000 {
		t.Errorf("collectedAt = %v, want it carried through", got.CollectedAt)
	}
}

// The page is one document with both scripts inlined. Serving the raw HTML file
// instead would leave the browser asking for wg_model.js on a route that does
// not exist, and the dashboard would come up blank.
func TestDashboardServesTheInlinedPage(t *testing.T) {
	mux := dashboardMux(testSnapshot(), wireguard.NewState(), time.Second, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/ = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type = %q, want text/html", ct)
	}
	if body := rec.Body.String(); strings.Contains(body, `<script src="wg_model.js">`) {
		t.Error("the page still points at wg_model.js as a separate file; nothing routes it")
	}
}

// The stream opens with a frame rather than with one interval of silence. A page
// that showed nothing until the first tick read as a page that had failed.
func TestDashboardEventStreamSendsAFrameBeforeTheFirstTick(t *testing.T) {
	done := make(chan struct{})
	// An interval long enough that a tick cannot be what produced the frame.
	mux := dashboardMux(testSnapshot(), wireguard.NewState(), time.Hour, done)

	srv := httptest.NewServer(mux)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("content type = %q, want text/event-stream", ct)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if !strings.HasPrefix(line, "data: ") {
		t.Errorf("first frame = %q, want an SSE data line", line)
	}
	close(done)
}

// Closing done ends the stream. Without it, a browser left open after Ctrl-C
// holds a handler ticking forever against a state nothing updates, and the
// process does not exit.
func TestDashboardEventStreamEndsWhenThePollerStops(t *testing.T) {
	done := make(chan struct{})
	mux := dashboardMux(testSnapshot(), wireguard.NewState(), time.Hour, done)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	defer resp.Body.Close()

	r := bufio.NewReader(resp.Body)
	if _, err := r.ReadString('\n'); err != nil { // the opening frame
		t.Fatalf("read first frame: %v", err)
	}
	close(done)

	// The handler returns, so the body reaches EOF. Reading to the end is the
	// assertion: a stream that ignored done would block here until the context
	// deadline and fail with a timeout instead.
	ended := make(chan error, 1)
	go func() {
		for {
			if _, err := r.ReadString('\n'); err != nil {
				ended <- err
				return
			}
		}
	}()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the event stream is still open after the poller stopped")
	}
}
