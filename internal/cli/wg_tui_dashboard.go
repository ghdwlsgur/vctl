package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/wireguard"
)

// Status is deliberately about evidence, not end-to-end reachability. A fresh
// handshake on one end is not proof that both ends or the routed networks work.
func (m wgTUI) tunnelStatus(e wireguard.Edge) string {
	_, a := m.observation(e, e.A)
	_, b := m.observation(e, e.B)
	if e.Conflict {
		return "conflict"
	}
	for _, status := range []string{"poll failed", "stale", "no handshake", "idle"} {
		if a == status || b == status {
			return status
		}
	}
	if a == "recent HS" && b == "recent HS" {
		return "recent HS"
	}
	if a == "recent HS" || b == "recent HS" {
		return "one-sided"
	}
	return "unobserved"
}

func (m wgTUI) traffic(e wireguard.Edge) (forward, reverse float64, observed bool) {
	for i, side := range []*wireguard.EdgeSide{e.A, e.B} {
		s, status := m.observation(e, side)
		if !s.RateReady || (status != "recent HS" && status != "idle" && status != "no handshake") {
			continue
		}
		if i == 0 {
			return s.TxPS, s.RxPS, true
		}
		return s.RxPS, s.TxPS, true
	}
	return 0, 0, false
}

func dashboardBadge(status string) string {
	glyph := "?"
	switch status {
	case "recent HS":
		glyph = "●"
	case "one-sided":
		glyph = "◐"
	case "idle":
		glyph = "○"
	case "poll failed", "conflict":
		glyph = "!"
	case "stale", "no handshake":
		glyph = "△"
	}
	return wgTUIColor(status).Render(glyph + " " + status)
}

// A row is a site pair, not a peer. Every edge is oriented to that row so
// left-to-right rates remain consistent even if the DB stored it in reverse.
type wgConnection struct {
	left, right string
	edges       []wireguard.Edge
}

func (m wgTUI) site(id string) string {
	if n, ok := m.nodes[id]; ok {
		if n.DC != "" {
			return n.DC
		}
		if n.Label != "" {
			return "소속 미확인 · " + n.Label
		}
	}
	return "소속 미확인 · " + id
}

func (m wgTUI) connections(edges []wireguard.Edge) []wgConnection {
	byPair := map[[2]string]*wgConnection{}
	for _, original := range edges {
		e := original
		a, b := m.site(e.Source), m.site(e.Target)
		if a > b || (a == b && e.Source > e.Target) {
			a, b = b, a
			e.Source, e.Target = e.Target, e.Source
			e.A, e.B = e.B, e.A
			e.Iface, e.Allowed = "", ""
			if e.A != nil {
				e.Iface, e.Allowed = e.A.Iface, e.A.Allowed
			}
		}
		key := [2]string{a, b}
		if byPair[key] == nil {
			byPair[key] = &wgConnection{left: a, right: b}
		}
		byPair[key].edges = append(byPair[key].edges, e)
	}
	out := []wgConnection{}
	for _, g := range byPair {
		sort.Slice(g.edges, func(i, j int) bool { return g.edges[i].ID < g.edges[j].ID })
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].left != out[j].left {
			return out[i].left < out[j].left
		}
		return out[i].right < out[j].right
	})
	return out
}

func simpleStatus(status string) string {
	labels := map[string]string{
		"recent HS": "● 최근 handshake", "one-sided": "◐ 한쪽만 확인",
		"idle": "○ handshake 오래됨", "no handshake": "△ handshake 없음",
		"stale": "△ 관측 오래됨", "poll failed": "! 수집 실패",
		"conflict": "! 식별 정보 충돌", "unobserved": "? 미관측",
	}
	return wgTUIColor(status).Render(labels[status])
}

func (m wgTUI) connectionState(g wgConnection) string {
	counts := map[string]int{}
	for _, e := range g.edges {
		counts[m.tunnelStatus(e)]++
	}
	if len(counts) == 1 {
		for status := range counts {
			return simpleStatus(status)
		}
	}
	return fmt.Sprintf("최근 %d · 확인 필요 %d · 미관측 %d", counts["recent HS"], len(g.edges)-counts["recent HS"]-counts["unobserved"], counts["unobserved"])
}

type wgNetworkInfo struct{ name, address string }

// Only an explicit attached-to relation identifies a local network. Inventory
// /24 aggregates, gateway management IPs and carries paths do not prove this.
// The opposite peer's AllowedIPs are shown separately as configured routes,
// never promoted into a confirmed local subnet or a successful reachability test.
func (m wgTUI) networkInfo(id string, opposite *wireguard.EdgeSide) wgNetworkInfo {
	entries := []string{}
	var single wgNetworkInfo
	for _, link := range m.topo.Links {
		if link.Kind != "attached-to" {
			continue
		}
		other := ""
		if link.Source == id {
			other = link.Target
		} else if link.Target == id {
			other = link.Source
		}
		n, ok := m.nodes[other]
		if !ok || n.Kind != "network" {
			continue
		}
		cidr, _ := n.Attrs["cidr"].(string)
		label := n.Label
		if label == "" {
			label = "등록된 네트워크"
		}
		single = wgNetworkInfo{label, cidr}
		if single.address == "" {
			single.address = "주소 미등록"
		}
		entries = append(entries, strings.TrimSpace(label+" "+cidr))
	}
	sort.Strings(entries)
	if len(entries) == 1 {
		return single
	}
	if len(entries) > 0 {
		return wgNetworkInfo{"등록된 네트워크", strings.Join(entries, ", ")}
	}
	info := wgNetworkInfo{"네트워크 미확인", "경로 미확인"}
	if opposite != nil && strings.TrimSpace(opposite.Allowed) != "" {
		info.address = "설정상 목적지: " + opposite.Allowed
	}
	return info
}

func (m wgTUI) gateway(id string) string {
	if n, ok := m.nodes[id]; ok && n.Label != "" {
		return n.Label
	}
	return id
}

func (m wgTUI) connectionDiagram(e wireguard.Edge, width int) []string {
	left, right := m.networkInfo(e.Source, e.B), m.networkInfo(e.Target, e.A)
	var lines []string
	if width >= 64 {
		gap := 18
		col := (width - gap) / 2
		pair := func(a, b string) string {
			return ui.PadRight(ansi.Truncate(a, col, "…"), col) + strings.Repeat(" ", gap) + ansi.Truncate(b, col, "…")
		}
		gateway := ansi.Truncate(m.gateway(e.Source), col-2, "…")
		link := gateway + " " + ui.Title(strings.Repeat("═", col-lipgloss.Width(gateway)-1)+"══ WireGuard ════ ")
		lines = []string{
			pair(ui.Title(m.site(e.Source)), ui.Title(m.site(e.Target))),
			pair(left.name, right.name), pair(left.address, right.address),
			pair("       │", "       │"),
			link + ansi.Truncate(m.gateway(e.Target), col, "…"),
		}
	} else {
		lines = []string{ui.Title(m.site(e.Source)) + " · " + left.name, left.address, "  │ " + m.gateway(e.Source), "  ║ WireGuard", "  │ " + m.gateway(e.Target), ui.Title(m.site(e.Target)) + " · " + right.name, right.address}
	}
	lines = append(lines, "", simpleStatus(m.tunnelStatus(e)))
	if f, r, ok := m.traffic(e); ok {
		lines = append(lines, m.site(e.Source)+" → "+m.site(e.Target)+"  "+humanRate(f), m.site(e.Target)+" → "+m.site(e.Source)+"  "+humanRate(r))
	} else {
		lines = append(lines, ui.Muted("트래픽 미확인 · 최신 관측 2회 필요"))
	}
	return lines
}

func (m wgTUI) architectureDetails(e wireguard.Edge) []string {
	out := []string{ui.Title("SELECTED TUNNEL"), dashboardBadge(m.tunnelStatus(e))}
	left, right := m.networkInfo(e.Source, e.B), m.networkInfo(e.Target, e.A)
	out = append(out, "왼쪽: "+left.name+" · "+left.address, "오른쪽: "+right.name+" · "+right.address)
	out = append(out, m.detail(e)[1:]...)
	for _, id := range []string{e.Source, e.Target} {
		n := m.nodes[id]
		if n.IP != "" {
			out = append(out, n.Label+" underlay: "+n.IP)
		}
		if n.TunnelIP != "" {
			out = append(out, n.Label+" tunnel IP: "+n.TunnelIP)
		}
		if n.Parent != "" {
			out = append(out, "Placed on: "+m.endpoint(n.Parent))
		}
		for _, warning := range n.Warnings {
			out = append(out, ui.Warn(warning))
		}
	}
	if m.topo.Derived != nil {
		for _, p := range m.topo.Derived.Paths {
			if p.Tunnel != e.Source && p.Tunnel != e.Target {
				continue
			}
			out = append(out, ui.Title("DECLARED PATH · "+p.Method), p.CIDR)
			for _, hop := range p.Hops {
				out = append(out, "  → "+m.endpoint(hop))
			}
			if p.Uncollected {
				out = append(out, ui.Warn("Not confirmed by collection"))
			}
		}
		for _, g := range m.topo.Derived.Gaps {
			if g.Subject == e.Source || g.Subject == e.Target {
				out = append(out, ui.Warn(g.Kind+": "+g.Detail))
			}
		}
	}
	out = append(out, "", ui.Muted("설정상 목적지는 반대편 peer의 AllowedIPs입니다."), ui.Muted("Handshake는 실제 네트워크 접근 성공을 보장하지 않습니다."))
	return out
}

// View is header, then either the details pane or the connection list with
// the selected tunnel's diagram, then the footer — cut to the terminal's
// height and every line truncated to its width, so a narrow or short
// terminal gets a shorter map rather than a wrapped one.
func (m wgTUI) View() string {
	w := max(1, m.width)
	groups := m.connections(m.edges())
	selected := max(0, min(m.cursor, len(groups)-1))
	lines := m.viewHeader()
	footer := m.footer(w)
	if len(groups) == 0 {
		lines = append(lines, "일치하는 연결이 없습니다. Esc로 검색을 지우세요.")
	} else {
		g := groups[selected]
		idx := max(0, min(m.tunnel, len(g.edges)-1))
		if m.showDetails {
			footer = "PgUp/PgDn 스크롤 · d/Esc 돌아가기 · q 종료"
			lines = append(lines, m.viewDetails(g.edges[idx], len(lines))...)
		} else {
			lines = append(lines, m.viewConnections(groups, selected, idx, w, len(lines))...)
		}
	}
	if m.height > 0 && len(lines) >= m.height {
		lines = lines[:max(0, m.height-1)]
	}
	lines = append(lines, footer)
	for i, line := range lines {
		lines[i] = ansi.Truncate(strings.ReplaceAll(strings.ReplaceAll(line, "\n", " "), "\r", " "), w, "…")
	}
	return strings.Join(lines, "\n") + "\n"
}

// viewHeader summarises the whole topology — not the filtered list — so the
// totals read the same whatever the search shows: title and mode, counts by
// status, the age of the collection with poll failures and drift, one blank.
func (m wgTUI) viewHeader() []string {
	counts := map[string]int{}
	for _, e := range m.topo.Edges {
		counts[m.tunnelStatus(e)]++
	}
	mode := "실시간 · " + m.interval.String()
	if m.state == nil {
		mode = "저장된 구조 · 실시간 조회 없음"
	}
	lines := []string{ui.Title("WireGuard 연결") + "  " + ui.Muted(mode), fmt.Sprintf("연결 %d · 터널 %d   최근 handshake %d · 확인 필요 %d · 미관측 %d", len(m.connections(m.topo.Edges)), len(m.topo.Edges), counts["recent HS"], len(m.topo.Edges)-counts["recent HS"]-counts["unobserved"], counts["unobserved"])}
	age := "구조 수집 이력 없음"
	if !m.topo.CollectedAt.IsZero() {
		age = fmt.Sprintf("구조 수집: %s 전", max(time.Duration(0), m.now.Sub(m.topo.CollectedAt)).Round(time.Second))
	}
	if len(m.live.Errors) > 0 {
		age += fmt.Sprintf(" · 수집 실패 %d", len(m.live.Errors))
	}
	if len(m.live.Drift) > 0 {
		age += fmt.Sprintf(" · 새 peer %d: sync 필요", len(m.live.Drift))
	}
	return append(lines, ui.Muted(age), "")
}

// footer is the key legend for the list mode, shortened for narrow
// terminals; while a filter is being typed or is in force it shows the filter.
func (m wgTUI) footer(w int) string {
	footer := "↑↓ 연결 · ←→ 터널 · Enter 접기/펼침 · d 상세 · / 검색 · q 종료"
	if w < 64 {
		footer = "↑↓ 선택 · Enter · d 상세 · q 종료"
	}
	if w < 32 {
		footer = "q 종료"
	}
	if m.editing || m.filter != "" {
		footer = "/ " + m.filter + " · Enter 적용 · Esc 초기화"
	}
	return footer
}

// viewDetails is the technical pane for one tunnel, scrolled by panY and cut
// to what fits under the header (used lines) with one line left for the footer.
func (m wgTUI) viewDetails(e wireguard.Edge, used int) []string {
	details := m.architectureDetails(e)
	capacity := len(details)
	if m.height > 0 {
		capacity = max(1, m.height-used-1)
	}
	start := min(m.panY, max(0, len(details)-capacity))
	return details[start:min(len(details), start+capacity)]
}

// viewConnections is the list of site connections around the selection, then
// — unless folded — the selected tunnel's diagram. The list gets what height
// remains after the diagram, so the diagram is never pushed off the screen by
// a long list.
func (m wgTUI) viewConnections(groups []wgConnection, selected, idx, w, used int) []string {
	g := groups[selected]
	e := g.edges[idx]
	diagram := m.connectionDiagram(e, w)
	if m.collapsed {
		diagram = nil
	}
	capacity := min(5, len(groups))
	if m.height > 0 {
		capacity = max(1, min(capacity, m.height-used-len(diagram)-3))
	} else {
		capacity = len(groups)
	}
	start := max(0, selected-capacity+1)
	var lines []string
	for i := start; i < min(len(groups), start+capacity); i++ {
		row := groups[i]
		mark := "  "
		if i == selected {
			mark = "▶ "
		}
		name := row.left + " ↔ " + row.right
		if i == selected {
			name = ui.Title(name)
		}
		name = ansi.Truncate(name, max(12, w-35), "…")
		lines = append(lines, mark+name+fmt.Sprintf(" · %d터널 · ", len(row.edges))+m.connectionState(row))
	}
	if len(groups) > capacity {
		lines = append(lines, ui.Muted(fmt.Sprintf("연결 %d–%d / %d · ↑↓로 이동", start+1, min(len(groups), start+capacity), len(groups))))
	}
	if !m.collapsed {
		lines = append(lines, "")
		if len(g.edges) > 1 {
			lines = append(lines, ui.Muted(fmt.Sprintf("이 연결의 터널 %d/%d · ←→로 선택", idx+1, len(g.edges))))
		}
		lines = append(lines, diagram...)
	}
	return lines
}
