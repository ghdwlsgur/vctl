package cli

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

func tuiFixture() wgTUI {
	m := newWGTUI(wireguard.Topology{
		Nodes: []wireguard.Node{{ID: "a", Label: "gateway-a", DC: "site-a"}, {ID: "b", Label: "gateway-b", DC: "site-b"}},
		Edges: []wireguard.Edge{{ID: "ab", Source: "a", Target: "b", Iface: "wg0", A: &wireguard.EdgeSide{Host: "a", Iface: "wg0", Allowed: "10.1.0.0/24"}, B: &wireguard.EdgeSide{Host: "b", Iface: "wg1", Allowed: "10.2.0.0/24"}}},
	}, 2*time.Second)
	m.now = time.Unix(1000, 0)
	m.live = wireguard.LiveSnapshot{Edges: map[string]wireguard.EdgeStat{"ab": {Sides: map[string]wireguard.EdgeSideStat{
		"a": {At: 999, HS: 10, TxPS: 2048, RxPS: 1024, RateReady: true},
		"b": {At: 999, HS: 10, TxPS: 1024, RxPS: 2048, RateReady: true},
	}}}, Errors: map[string]string{}}
	return m
}

func TestWGTUIDirectionAndFailures(t *testing.T) {
	m := tuiFixture()
	e := m.topo.Edges[0]
	want := "A → B  " + humanRate(2048) + "    B → A  " + humanRate(1024)
	if got := strings.Join(m.detail(e), "\n"); !strings.Contains(got, want+"  (A counters)") {
		t.Fatal(got)
	}
	m.live.Errors["a"] = "SSH unavailable"
	if got := strings.Join(m.detail(e), "\n"); !strings.Contains(got, want+"  (B counters)") || !strings.Contains(got, "poll failed") {
		t.Fatal(got)
	}
	m.now = m.now.Add(time.Minute)
	if got := strings.Join(m.detail(e), "\n"); !strings.Contains(got, "waiting for observation") {
		t.Fatal("stale rate shown:", got)
	}
}

func TestWGTUIFilterAndSize(t *testing.T) {
	m := tuiFixture()
	for _, size := range [][2]int{{120, 40}, {80, 24}, {40, 12}, {16, 5}} {
		m.width, m.height = size[0], size[1]
		view := strings.TrimSuffix(m.View(), "\n")
		lines := strings.Split(view, "\n")
		if len(lines) > m.height {
			t.Fatalf("height %d: %d", m.height, len(lines))
		}
		for _, line := range lines {
			if lipgloss.Width(line) > m.width {
				t.Fatalf("width %d: %q", m.width, line)
			}
		}
	}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("missing")})
	filtered := model.(wgTUI)
	if len(filtered.edges()) != 0 {
		t.Fatal("filter ignored")
	}
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if len(model.(wgTUI).edges()) != 1 {
		t.Fatal("escape did not clear filter")
	}
	filtered.filter = "10.2.0"
	if len(filtered.edges()) != 1 {
		t.Fatal("far-end AllowedIPs missing from search")
	}
}

func TestWGTUIObservationStates(t *testing.T) {
	m := tuiFixture()
	e := m.topo.Edges[0]
	for _, tc := range []struct {
		hs, at int64
		want   string
	}{{10, 999, "recent HS"}, {200, 999, "idle"}, {-1, 999, "no handshake"}, {10, 900, "stale"}} {
		m.live.Edges[e.ID].Sides["a"] = wireguard.EdgeSideStat{HS: tc.hs, At: tc.at}
		if _, got := m.observation(e, e.A); got != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
	if _, got := m.observation(e, nil); got != "unobserved" {
		t.Fatal(got)
	}
}

func TestWGTUISimplePreview(t *testing.T) {
	m := tuiFixture()
	m.state = wireguard.NewState()
	m.topo.CollectedAt = m.now
	m.nodes["a"] = wireguard.Node{ID: "a", Label: "서울 게이트웨이", DC: "서울"}
	m.nodes["b"] = wireguard.Node{ID: "b", Label: "인천 게이트웨이", DC: "인천"}
	m.nodes["net-a"] = wireguard.Node{ID: "net-a", Kind: "network", Label: "업무망", Attrs: map[string]any{"cidr": "10.10.0.0/24"}}
	m.nodes["net-b"] = wireguard.Node{ID: "net-b", Kind: "network", Label: "서비스망", Attrs: map[string]any{"cidr": "10.20.0.0/24"}}
	m.topo.Links = []wireguard.Link{{Source: "a", Target: "net-a", Kind: "attached-to"}, {Source: "b", Target: "net-b", Kind: "attached-to"}}
	m.width, m.height = 80, 24
	view := m.View()
	for _, want := range []string{"서울 ↔ 인천", "서울 게이트웨이", "인천 게이트웨이", "업무망", "서비스망", "WireGuard", "서울 → 인천", "인천 → 서울"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %s:\n%s", want, view)
		}
	}
	for _, technical := range []string{"AllowedIPs", "wg0", "SELECTED TUNNEL", "underlay"} {
		if strings.Contains(view, technical) {
			t.Fatalf("technical detail leaked: %s", technical)
		}
	}
	t.Log("\n" + view)
}

func TestWGConnectionsOrientBothDirectionsAndKeepParallelTunnels(t *testing.T) {
	m := tuiFixture()
	first := m.topo.Edges[0]
	reverse := first
	reverse.ID = "ba"
	reverse.Source, reverse.Target = "b", "a"
	reverse.A, reverse.B = first.B, first.A
	m.live.Edges["ba"] = m.live.Edges["ab"]
	m.topo.Edges = append(m.topo.Edges, reverse)
	groups := m.connections(m.topo.Edges)
	if len(groups) != 1 || len(groups[0].edges) != 2 {
		t.Fatal(groups)
	}
	for _, e := range groups[0].edges {
		if e.Source != "a" || e.A.Host != "a" || e.B.Host != "b" {
			t.Fatal("orientation mismatch", e)
		}
		f, r, ok := m.traffic(e)
		if !ok || f != 2048 || r != 1024 {
			t.Fatal("reversed or double-counted traffic", f, r, ok)
		}
	}
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	if model.(wgTUI).tunnel != 1 {
		t.Fatal("parallel tunnel inaccessible")
	}
}

func TestWGUnknownNetworkIsNotInventedFromInventoryOrRoutes(t *testing.T) {
	m := tuiFixture()
	e := m.topo.Edges[0]
	m.nodes["a"] = wireguard.Node{ID: "a", Label: "gateway-a", IP: "10.99.0.1", DC: "site-a"}
	m.topo.Aggs = []wireguard.Agg{{ID: "agg", DC: "site-a", CIDR: "10.99.0.0/24"}}
	m.topo.Links = []wireguard.Link{{Source: "a", Target: "agg", Kind: "network"}}
	info := m.networkInfo("a", e.B)
	if info.name != "네트워크 미확인" || !strings.Contains(info.address, e.B.Allowed) || strings.Contains(info.address, e.A.Allowed) {
		t.Fatal(info)
	}
	if got := m.networkInfo("a", nil); got.address != "경로 미확인" {
		t.Fatal(got)
	}
	m.nodes["x"] = wireguard.Node{ID: "x", Label: "외부1"}
	m.nodes["y"] = wireguard.Node{ID: "y", Label: "외부2"}
	groups := m.connections([]wireguard.Edge{{Source: "a", Target: "x"}, {Source: "a", Target: "y"}})
	if len(groups) != 2 {
		t.Fatal("unrelated unknown sites merged", groups)
	}
}

func TestWGConnectionFoldDetailsAndSearch(t *testing.T) {
	m := tuiFixture()
	model, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !model.(wgTUI).collapsed || strings.Contains(model.(wgTUI).View(), "gateway-a") {
		t.Fatal("diagram did not fold")
	}
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	if !strings.Contains(model.(wgTUI).View(), "AllowedIPs") {
		t.Fatal("technical detail inaccessible")
	}
	model, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.(wgTUI).showDetails {
		t.Fatal("Escape did not close details")
	}
	m.filter = "no matches"
	if !strings.Contains(m.View(), "일치하는 연결이 없습니다") {
		t.Fatal(m.View())
	}
}

func TestWGSimpleStateAndStaleTraffic(t *testing.T) {
	m := tuiFixture()
	e := m.topo.Edges[0]
	delete(m.live.Edges[e.ID].Sides, "b")
	if m.tunnelStatus(e) != "one-sided" {
		t.Fatal("partial observation shown as both ends healthy")
	}
	m.live.Errors["b"] = "failed"
	if m.tunnelStatus(e) != "poll failed" {
		t.Fatal("poll failure hidden")
	}
	m.now = m.now.Add(time.Minute)
	if _, _, ok := m.traffic(e); ok {
		t.Fatal("stale traffic displayed")
	}
}
