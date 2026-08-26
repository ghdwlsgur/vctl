// Package motd renders a login banner from the inventory's view of the host's
// OpenStack farm, and keeps a file on disk matching it.
//
// The banner it replaces was maintained by hand, and the hand-maintained copy
// on the machine that prompted this was two months stale — it named a
// controller the control plane had stopped reporting. The data it repeats
// (which farm, who is the controller, which machines are the computes) is
// exactly what the reconciler already keeps in Postgres, so the honest source
// is a render of that, stamped with when the reconciler last looked rather
// than when somebody last remembered to edit a file.
package motd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// Banner is everything a render needs beyond the topology itself.
type Banner struct {
	// Header is the org's masthead — ASCII art and whatever fixed lines belong
	// above the computed ones. Org-specific, so it lives in config defaults,
	// not here.
	Header string
	// ManagedBy is the fixed attribution line under the role line.
	ManagedBy string
	// Self is the inventory hostname of the machine the file is written on;
	// its row gets the marker.
	Self string
}

// Render produces the complete banner, or "" when the host is in no farm —
// the caller treats "" as "leave the file alone", so a machine that is not an
// OpenStack member never has its MOTD claimed by this code.
func Render(b Banner, farms []store.FarmTopology) string {
	if len(farms) == 0 {
		return ""
	}
	var out strings.Builder
	if h := strings.TrimRight(b.Header, "\n"); h != "" {
		out.WriteString(h)
		out.WriteString("\n\n")
	}

	// The role line describes the machine, not a farm, so it is computed
	// across all of them (controller anywhere wins) and printed once.
	role := "Compute"
	var synced time.Time
	sections := make([]string, 0, len(farms))
	for _, f := range farms {
		rows, isController, unclaimed := topologyRows(b.Self, f)
		if isController {
			role = "Controller"
		}
		if f.SyncedAt.After(synced) {
			synced = f.SyncedAt
		}
		sections = append(sections, section(f, rows, unclaimed))
	}

	fmt.Fprintf(&out, "This server is an OpenStack %s Node.\n", role)
	if b.ManagedBy != "" {
		out.WriteString(b.ManagedBy)
		out.WriteString("\n")
	}
	for _, f := range farms {
		if f.Team != "" {
			fmt.Fprintf(&out, "Used by %s team.\n", f.Team)
			break
		}
	}
	for _, s := range sections {
		out.WriteString("\n")
		out.WriteString(s)
	}

	// The reconciler's clock, not this render's. A fresh render of stale data
	// stamped "now" would be the exact lie the hand-maintained file told.
	if !synced.IsZero() {
		fmt.Fprintf(&out, "\nLast synced: %s\n", synced.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	return out.String()
}

// row is one line of the topology table, already classified.
type row struct {
	label    string // "Controller" or "Compute #n"
	addr     string // the member's inventory IP
	hostname string
	novaName string // set when the control plane calls this machine something else
	here     bool
}

// topologyRows classifies a farm's members into controller and compute lines,
// and reports whether self is one of the controllers, plus any control-plane
// names that could be attached to no member at all.
//
// Controller identity comes from the capability probe (FarmMember.Controller),
// never from the ghost names — those are the opposite: names the control
// plane reports that matched NO inventory host. Each of those is first
// pinned to a member when only one member's name is a near miss (the farm that
// prompted this has a compute whose nova.conf says "sre-svr-…" for a machine
// the inventory calls "sre-srv-…"); the pinned row then shows the member's real
// IP with the control plane's spelling beside it. A name with zero or several
// near misses stays unattached and is rendered as a warning line — guessing
// would put the banner's arrow on the wrong machine.
func topologyRows(self string, f store.FarmTopology) (rows []row, selfIsController bool, unclaimed []string) {
	novaName := map[string]string{}

	local := make([]string, 0, len(f.Members))
	for _, m := range f.Members {
		local = append(local, m.Hostname)
	}
	pairs, _ := membership.MatchHosts(local, f.GhostNames)
	claimed := map[string]bool{}
	for host, c := range pairs {
		novaName[host] = c
		claimed[c] = true
	}
	for _, c := range f.GhostNames {
		if claimed[c] {
			continue
		}
		var hits []string
		for _, m := range f.Members {
			if _, taken := novaName[m.Hostname]; !taken && nearlySame(m.Hostname, c) {
				hits = append(hits, m.Hostname)
			}
		}
		if len(hits) == 1 {
			novaName[hits[0]] = c
			continue
		}
		unclaimed = append(unclaimed, c)
	}

	for _, m := range f.Members {
		if m.Controller {
			rows = append(rows, row{label: "Controller", addr: m.IP, hostname: m.Hostname,
				novaName: novaName[m.Hostname], here: m.Hostname == self})
			if m.Hostname == self {
				selfIsController = true
			}
		}
	}
	n := 0
	for _, m := range f.Members {
		if m.Controller {
			continue
		}
		n++
		rows = append(rows, row{label: fmt.Sprintf("Compute #%d", n), addr: m.IP, hostname: m.Hostname,
			novaName: novaName[m.Hostname], here: m.Hostname == self})
	}
	return rows, selfIsController, unclaimed
}

// nearlySame reports whether two host names differ by at most one typo — one
// substituted, inserted, or deleted character, or one adjacent transposition
// (Damerau-Levenshtein distance ≤ 1), ignoring case and domain suffixes.
//
// This deliberately does NOT live in membership.MatchHosts: pairing on a typo
// is fine for putting an IP next to a name on a banner, and wrong for deciding
// membership — the reconciler must keep reporting the mismatch until somebody
// fixes the nova.conf that causes it.
func nearlySame(a, b string) bool {
	a = strings.ToLower(shortHost(a))
	b = strings.ToLower(shortHost(b))
	if a == b {
		return true
	}
	if len(a) == len(b) {
		i := 0
		for a[i] == b[i] {
			i++
		}
		if a[i+1:] == b[i+1:] { // one substitution
			return true
		}
		// one adjacent transposition
		return i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
	}
	long, short := a, b
	if len(b) > len(a) {
		long, short = b, a
	}
	if len(long)-len(short) != 1 {
		return false
	}
	i := 0
	for i < len(short) && long[i] == short[i] {
		i++
	}
	return long[i+1:] == short[i:] // one insertion
}

// shortHost drops a domain suffix; sre-srv-0059.internal and sre-srv-0059 are
// one machine. (membership has the same helper, unexported.)
func shortHost(h string) string {
	if s, _, ok := strings.Cut(h, "."); ok {
		return s
	}
	return h
}

// section renders one farm's topology block with aligned columns.
func section(f store.FarmTopology, rows []row, unclaimed []string) string {
	var out strings.Builder
	title := "[ Cluster Topology ]"
	if f.DisplayName != "" {
		title = fmt.Sprintf("[ Cluster Topology — %s ]", f.DisplayName)
	}
	out.WriteString(title)
	out.WriteString("\n")
	if f.State != "" && f.State != "active" {
		note := f.State
		if f.StateNote != "" {
			note += ": " + f.StateNote
		}
		fmt.Fprintf(&out, "  !! farm state is %s\n", note)
	}

	labelW, addrW := 0, 0
	for _, r := range rows {
		labelW = max(labelW, len(r.label))
		addrW = max(addrW, len(r.addr))
	}
	for _, r := range rows {
		name := r.hostname
		if r.novaName != "" {
			name += fmt.Sprintf(", nova calls it %q", r.novaName)
		}
		fmt.Fprintf(&out, "  %-*s : %-*s  (%s)", labelW, r.label, addrW, r.addr, name)
		if r.here {
			out.WriteString("  <- HERE")
		}
		out.WriteString("\n")
	}
	if len(unclaimed) > 0 {
		fmt.Fprintf(&out, "  !! nova reports hosts the inventory does not know: %s\n",
			strings.Join(unclaimed, ", "))
	}
	return out.String()
}

// Sync makes the file at path hold exactly content, atomically, and reports
// whether it changed anything. An unchanged file is untouched — its mtime is
// how an operator tells "the topology changed last week" from "the agent
// rewrote the same bytes five minutes ago".
func Sync(path, content string) (changed bool, err error) {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		return false, nil
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".motd-*")
	if err != nil {
		// Under ProtectSystem=strict only the file itself is bind-mounted
		// writable (ReadWritePaths=/etc/motd) — the directory stays read-only,
		// so a sibling temp file cannot exist and the rename dance is not
		// available. Truncate-and-write in place instead: not atomic, but the
		// banner is one small write, a torn read costs a cosmetic prompt, and
		// the next pass rewrites it.
		return true, os.WriteFile(path, []byte(content), 0o644)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return false, err
	}
	// pam_motd reads it as any user; CreateTemp's 0600 would hide the banner
	// from everyone but root.
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, err
	}
	return true, nil
}
