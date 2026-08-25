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
		rows, isController := topologyRows(b.Self, f)
		if isController {
			role = "Controller"
		}
		if f.SyncedAt.After(synced) {
			synced = f.SyncedAt
		}
		sections = append(sections, section(f, rows))
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
	addr     string // IP, or a note when the machine is only a control-plane name
	hostname string
	here     bool
}

// topologyRows classifies a farm's members into controller and compute lines,
// and reports whether self is one of the controllers.
//
// Controller identity comes from pairing the control plane's host list against
// the members. The names differ (nova says aio01, the inventory says
// incheon-aio01), so exact evidence is tried first and membership.MatchHosts
// handles the rest. A control name that matches nothing still gets a line: on
// the farm that prompted this, nova reports a name with a typo in it
// ("sre-svr-…"), and showing the unmatched name at the login prompt is how a
// human finds that out.
func topologyRows(self string, f store.FarmTopology) (rows []row, selfIsController bool) {
	controllers := map[string]bool{}
	matched := map[string]bool{}

	byNova := map[string]string{}
	local := make([]string, 0, len(f.Members))
	for _, m := range f.Members {
		local = append(local, m.Hostname)
		if m.NovaHostname != "" {
			byNova[m.NovaHostname] = m.Hostname
		}
	}
	var loose []string
	for _, c := range f.ControlNames {
		if host, ok := byNova[c]; ok {
			controllers[host] = true
			matched[c] = true
			continue
		}
		loose = append(loose, c)
	}
	pairs, _ := membership.MatchHosts(local, loose)
	for host, c := range pairs {
		controllers[host] = true
		matched[c] = true
	}

	for _, m := range f.Members {
		if controllers[m.Hostname] {
			rows = append(rows, row{label: "Controller", addr: m.IP, hostname: m.Hostname, here: m.Hostname == self})
			if m.Hostname == self {
				selfIsController = true
			}
		}
	}
	for _, c := range f.ControlNames {
		if !matched[c] {
			rows = append(rows, row{label: "Controller", addr: "?", hostname: c + " (control plane name, not in inventory)"})
		}
	}
	n := 0
	for _, m := range f.Members {
		if controllers[m.Hostname] {
			continue
		}
		n++
		rows = append(rows, row{label: fmt.Sprintf("Compute #%d", n), addr: m.IP, hostname: m.Hostname, here: m.Hostname == self})
	}
	return rows, selfIsController
}

// section renders one farm's topology block with aligned columns.
func section(f store.FarmTopology, rows []row) string {
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
		fmt.Fprintf(&out, "  %-*s : %-*s  (%s)", labelW, r.label, addrW, r.addr, r.hostname)
		if r.here {
			out.WriteString("  <- HERE")
		}
		out.WriteString("\n")
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
		return false, err
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
