package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func openstackFarmShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show [deployment]",
		Short: "One farm's architecture: which hosts hold which role, and what release they run",
		Long: "The flat listing answers \"which hosts run OpenStack\". This answers \"what is this\n" +
			"deployment built out of\" — the controllers, the compute fleet, the release drift,\n" +
			"and the hosts whose membership is not settled, in one screen.\n\n" +
			"The deployment can be named by its display name or its Keystone endpoint. With no\n" +
			"argument it is picked from a list.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withStore(cmd.Context(), false, func(_ *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, err := farmChoices(ctx, st)
				if err != nil {
					return err
				}
				if len(farms) == 0 {
					ui.Warnf(os.Stderr, "no deployments yet. Run the node agents, then 'vctl openstack'.")
					return nil
				}
				var pick farmChoice
				if len(args) > 0 {
					i := indexOfFarm(farms, args[0])
					if i < 0 {
						return fmt.Errorf("no deployment %q; run 'vctl openstack' to see them", args[0])
					}
					pick = farms[i]
				} else {
					if !isTerminal() {
						return fmt.Errorf("a deployment is required when there is no terminal to pick at")
					}
					i, err := pickIndex(farmPickLabels(farms), nil, "Show a deployment")
					if err != nil {
						return err
					}
					pick = farms[i]
				}
				hosts, err := st.OpenStackHosts(ctx)
				if err != nil {
					return err
				}
				view := buildFarmView(pick, hosts)
				if asJSON {
					return writeJSON(view)
				}
				renderFarmShow(os.Stdout, view)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (for dataset/agent export)")
	return cmd
}

// farmView is one deployment reshaped from per-host rows into an architecture:
// role sections a reader walks top-down, instead of nine comma-separated roles
// repeated across seven lines.
type farmView struct {
	ID     string `json:"id"`
	Name   string `json:"name,omitempty"`
	Region string `json:"region,omitempty"`

	Confirmed int `json:"confirmed"`
	Total     int `json:"total"`

	Sections []farmSection `json:"sections,omitempty"`

	// Releases counts hosts per release string, so drift is one line rather
	// than something the reader assembles by scanning a column.
	Releases map[string]int `json:"releases,omitempty"`

	// Unsettled are hosts whose membership rests on something weaker than
	// confirmation, each with the confidence that says why.
	Unsettled []string `json:"unsettled,omitempty"`
}

type farmSection struct {
	Role  string       `json:"role"`
	Hosts []farmMember `json:"hosts"`
}

type farmMember struct {
	Hostname string `json:"hostname"`
	Release  string `json:"release,omitempty"`
	// Roles is how many roles the host holds in total — the signal that a
	// "controller" is really an all-in-one.
	Roles int `json:"roles"`
	// AlsoIn is the earlier section this host already appeared under. Repeating
	// its release and role count there too would render the same facts twice
	// and make an all-in-one deployment read as twice its size.
	AlsoIn string `json:"also_in,omitempty"`
}

// roleOrder walks the architecture the way someone reasons about it: the
// control plane first, then what it controls, then the services around them.
// Roles outside this list follow alphabetically.
var roleOrder = []string{"controller", "compute", "network", "block-storage", "image", "identity", "dashboard", "orchestration", "load-balancer"}

func buildFarmView(pick farmChoice, all []store.OpenStackHost) farmView {
	v := farmView{ID: pick.ID, Name: pick.Name, Region: pick.Region, Releases: map[string]int{}}

	var members []store.OpenStackHost
	for _, h := range all {
		if h.Farm == pick.ID && h.Detected {
			members = append(members, h)
		}
	}
	v.Total = len(members)

	byRole := map[string][]store.OpenStackHost{}
	for _, h := range members {
		if h.Confidence == store.ConfidenceConfirmed {
			v.Confirmed++
		} else {
			v.Unsettled = append(v.Unsettled, fmt.Sprintf("%s (%s)", h.Hostname, h.Confidence))
		}
		v.Releases[releaseOf(h)]++
		for _, r := range h.Roles {
			byRole[r] = append(byRole[r], h)
		}
	}

	firstSeen := map[string]string{}
	for _, role := range orderedRoles(byRole) {
		hs := byRole[role]
		sort.Slice(hs, func(i, j int) bool { return hs[i].Hostname < hs[j].Hostname })
		sec := farmSection{Role: role}
		for _, h := range hs {
			m := farmMember{Hostname: h.Hostname, Release: releaseOf(h), Roles: len(h.Roles)}
			if prev, seen := firstSeen[h.Hostname]; seen {
				m.AlsoIn = prev
			} else {
				firstSeen[h.Hostname] = role
			}
			sec.Hosts = append(sec.Hosts, m)
		}
		v.Sections = append(v.Sections, sec)
	}
	sort.Strings(v.Unsettled)
	return v
}

func orderedRoles(byRole map[string][]store.OpenStackHost) []string {
	rank := map[string]int{}
	for i, r := range roleOrder {
		rank[r] = i
	}
	out := make([]string, 0, len(byRole))
	for r := range byRole {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, iOK := rank[out[i]]
		rj, jOK := rank[out[j]]
		switch {
		case iOK && jOK:
			return ri < rj
		case iOK != jOK:
			return iOK
		default:
			return out[i] < out[j]
		}
	})
	return out
}

// releaseOf is the one string that stands for what a host runs: nova's version
// where nova is present, the first component's otherwise. It deliberately
// matches how the flat listing summarises the same host, so the two views never
// disagree about a release.
func releaseOf(h store.OpenStackHost) string {
	if c, ok := h.Components["nova-compute"]; ok && c.Version != "" {
		return c.Version
	}
	names := make([]string, 0, len(h.Components))
	for name := range h.Components {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if v := h.Components[name].Version; v != "" {
			return v
		}
	}
	return "-"
}

func renderFarmShow(w io.Writer, v farmView) {
	title := v.ID
	if v.Name != "" {
		title = v.Name + " · " + v.ID
	}
	if v.Region != "" {
		title += " · " + v.Region
	}
	title += fmt.Sprintf(" · confirmed %d/%d", v.Confirmed, v.Total)
	ui.Section(w, title)

	if v.Total == 0 {
		// Named before anything reported, or every probe has gone quiet. Say
		// which world this is instead of printing an empty tree.
		fmt.Fprintln(w, ui.Muted("  no hosts have reported for this deployment"))
		return
	}

	for _, sec := range v.Sections {
		// A section whose every host already appeared above carries no new
		// facts, only the role's membership. One line says that; a tree of
		// "also controller" seven sections long buried the two sections that
		// actually said something.
		if repeats := allRepeats(sec); repeats != "" {
			fmt.Fprintf(w, "\n  %s %s  %s\n", ui.Value(sec.Role),
				ui.Muted(fmt.Sprintf("(%d)", len(sec.Hosts))), ui.Muted(repeats))
			continue
		}
		fmt.Fprintf(w, "\n  %s %s\n", ui.Value(sec.Role), ui.Muted(fmt.Sprintf("(%d)", len(sec.Hosts))))
		for i, m := range sec.Hosts {
			branch := "├─"
			if i == len(sec.Hosts)-1 {
				branch = "└─"
			}
			detail := ui.Muted("also " + m.AlsoIn)
			if m.AlsoIn == "" {
				detail = fmt.Sprintf("%-10s %s", m.Release, ui.Muted(roleCount(m.Roles)))
			}
			fmt.Fprintf(w, "  %s %s  %s\n", ui.Muted(branch), ui.PadRight(m.Hostname, 18), detail)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("release"), 20), releaseLine(v.Releases, v.Total))
	if len(v.Unsettled) > 0 {
		fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("unsettled"), 20),
			ui.Warn(strings.Join(v.Unsettled, ", ")))
	}
	fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("keystone"), 20), v.ID)
}

// allRepeats returns the compact membership line for a section whose every
// host was already shown, and "" when the section introduces anyone new.
func allRepeats(sec farmSection) string {
	names := make([]string, 0, len(sec.Hosts))
	for _, m := range sec.Hosts {
		if m.AlsoIn == "" {
			return ""
		}
		names = append(names, m.Hostname)
	}
	return strings.Join(names, " · ")
}

func roleCount(n int) string {
	if n == 1 {
		return "1 role"
	}
	return fmt.Sprintf("%d roles", n)
}

// releaseLine says in one line whether the farm is on one release or drifting —
// which is the question a farm view usually exists to answer.
func releaseLine(releases map[string]int, total int) string {
	if len(releases) == 1 {
		for r := range releases {
			return fmt.Sprintf("%s %s", r, ui.Muted(fmt.Sprintf("(all %d)", total)))
		}
	}
	keys := make([]string, 0, len(releases))
	for r := range releases {
		keys = append(keys, r)
	}
	// Largest first: the line reads "mostly X, with stragglers on Y".
	sort.Slice(keys, func(i, j int) bool {
		if releases[keys[i]] != releases[keys[j]] {
			return releases[keys[i]] > releases[keys[j]]
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, 0, len(keys))
	for _, r := range keys {
		parts = append(parts, fmt.Sprintf("%s ×%d", r, releases[r]))
	}
	return ui.Warn("drift: " + strings.Join(parts, " · "))
}
