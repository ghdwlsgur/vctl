package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/hoststatus"
	"github.com/ghdwlsgur/vctl/internal/openstack"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

func openstackFarmShowCmd(env CommandEnv) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show [deployment]",
		Short: "One farm's architecture: which hosts hold which role, and what release they run",
		Long: "The flat listing answers \"which hosts run OpenStack\". This answers \"what is this\n" +
			"deployment built out of\" — the controllers, the compute fleet, the release drift,\n" +
			"and the hosts whose membership is not settled, in one screen.\n\n" +
			"The deployment can be named by its display name or its Keystone endpoint. With no\n" +
			"argument it is picked from a list.",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: byPosition(completeFarm(env)),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := commandOutput(cmd, asJSON)
			if err != nil {
				return err
			}
			return env.withStore(cmd.Context(), false, func(a *app.App, st *store.Store) error {
				ctx := cmd.Context()
				farms, ok, err := farmChoicesForPick(ctx, a, st)
				if err != nil || !ok {
					return err
				}
				pick, err := pickFarm(farms, firstArg(args), "Show a deployment")
				if err != nil {
					return err
				}
				now := time.Now()
				assessment, err := collectAssessment(ctx, st, pick.ID, now)
				if err != nil {
					return err
				}
				if format != outputTable {
					return writeStructured(format, assessment)
				}
				renderFarmShow(os.Stdout, assessment, now)
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (for dataset/agent export)")
	return supportsStructuredOutput(cmd)
}

// farmStaleWindow is how old a successful reconcile may be before this view
// says so. The timer runs every six hours, so two missed runs.
const farmStaleWindow = 13 * time.Hour

// collectAssessment gathers what has been stored about one deployment and hands
// it to the domain package to judge.
//
// The judging used to be here. It moved because an API or a web view would have
// had to make the same calls — is this drifting, is this stale, is this host
// down — and two implementations of that disagree eventually, with no way to
// tell which one somebody is looking at.
// The selector settles which deployment; everything shown about it comes from
// the snapshot. It used to take a farmChoice and read the name, region and
// state off that — values read *before* the snapshot — so a `farm state` landing
// between the two put the old state on screen beside the new note. One read, one
// instant, and that has to mean all of it.
func collectAssessment(ctx context.Context, st *store.Store, id string, now time.Time) (openstack.Assessment, error) {
	// One read, one instant. This was five separate reads, and a reconcile
	// landing between the second and the third put a host count from before it
	// beside a run result from after it. Nothing on the screen says which number
	// came from when, so it is not something a reader can catch.
	snap, err := st.FarmSnapshot(ctx, id)
	if err != nil {
		return openstack.Assessment{}, err
	}
	in := openstack.Input{
		ID:    id,
		Hosts: snap.Hosts, Instances: snap.Instances, Ghosts: snap.Ghosts,
		Run:        snap.Run,
		StaleAfter: farmStaleWindow, Now: now,
	}
	// Name, region, state, note and its date all come from the same row read at
	// the same instant. A deployment nobody has named has none of them, which is
	// a different thing from a read that failed — DeploymentKnown says which,
	// and the failure is an error now rather than a blank screen.
	if snap.DeploymentKnown {
		d := snap.Deployment
		in.Name, in.Region, in.State = d.DisplayName, d.Region, d.State
		in.StateNote, in.StateSince = d.StateNote, d.StateChangedAt
	}
	return openstack.Assess(in), nil
}

func renderFarmShow(w io.Writer, a openstack.Assessment, now time.Time) {
	title := a.ID
	if a.Name != "" {
		title = a.Name + " · " + a.ID
	}
	if a.Region != "" {
		title += " · " + a.Region
	}
	title += fmt.Sprintf(" · confirmed %d/%d", a.Membership.Confirmed, a.Membership.Total)
	ui.Section(w, title)
	if line := declaredStateLine(a, now); line != "" {
		fmt.Fprintf(w, "  %s\n", line)
	}

	if a.Membership.Total == 0 {
		// Named before anything reported, or every probe has gone quiet. Say
		// which world this is instead of printing an empty tree.
		fmt.Fprintln(w, ui.Muted("  no hosts have reported for this deployment"))
		fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("reconciled"), 20), reconcileLine(a.Freshness, now))
		return
	}

	for _, sec := range a.Architecture.Sections {
		count := fmt.Sprintf("(%d)", len(sec.Hosts))
		if sec.Down > 0 {
			count += " " + ui.Warn(fmt.Sprintf("%d down", sec.Down))
		}
		// A section whose every host already appeared above carries no new
		// facts, only the role's membership. One line says that; a tree of
		// "also controller" seven sections long buried the two sections that
		// actually said something.
		if repeats := allRepeats(sec); repeats != "" {
			fmt.Fprintf(w, "\n  %s %s  %s\n", ui.Value(sec.Role), ui.Muted(count), ui.Muted(repeats))
			continue
		}
		fmt.Fprintf(w, "\n  %s %s\n", ui.Value(sec.Role), ui.Muted(count))
		for i, m := range sec.Hosts {
			branch := "├─"
			if i == len(sec.Hosts)-1 {
				branch = "└─"
			}
			detail := ui.Muted("also " + m.AlsoIn)
			if m.AlsoIn == "" {
				detail = fmt.Sprintf("%-10s %s", m.Release, ui.Muted(roleCount(m.Roles)))
				if m.VMs > 0 {
					detail += "  " + ui.Muted(fmt.Sprintf("%d VMs", m.VMs))
				}
			}
			if m.Down {
				detail += "  " + ui.Warn("down")
			}
			fmt.Fprintf(w, "  %s %s  %s\n", ui.Muted(branch), ui.PadRight(m.Hostname, 18), detail)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("release"), 20), releaseLine(a.Versions))
	if a.Architecture.VMs > 0 || a.Health.VMsMissing > 0 {
		fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("vms"), 20), vmLine(a))
	}
	if len(a.Membership.Unsettled) > 0 {
		fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("unsettled"), 20),
			ui.Warn(strings.Join(a.Membership.Unsettled, ", ")))
	}
	if len(a.Dashboard) > 0 {
		line := a.Dashboard[0]
		if len(a.Dashboard) > 1 {
			// The rest muted and in one line: they are the same dashboard from
			// somewhere else, not other dashboards.
			line += ui.Muted("  also " + strings.Join(a.Dashboard[1:], " "))
		}
		fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("dashboard"), 20), line)
	}
	if line := caTrustLine(a.CATrust); line != "" {
		fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("ca-trust"), 20), line)
	}
	fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("keystone"), 20), a.ID)
	fmt.Fprintf(w, "  %s %s\n", ui.PadRight(ui.Muted("reconciled"), 20), reconcileLine(a.Freshness, now))
	renderAnomalies(w, a.Anomalies, a.State)
}

// caTrustLine answers "will a VM created here trust vctl's certificates".
//
// It says which service was asked, because that is the part people get wrong,
// and it names the disagreeing hosts when a farm's controllers do not agree —
// "partly on" without saying which one is no use at three in the morning.
//
// Read from the deployed config, so a farm whose config landed but whose
// container has not been restarted yet still reads as on. The word is "config"
// rather than something stronger for exactly that reason.
func caTrustLine(c openstack.CATrust) string {
	if c.State == "" {
		return ""
	}
	svc := ""
	if len(c.Hosts) > 0 {
		svc = " · " + strconv.Itoa(len(c.Hosts)) + " metadata host(s)"
	}
	switch c.State {
	case hoststatus.VendordataOn:
		return ui.OK("on") + ui.Muted(" · new VMs trust the SSH CA"+svc)
	case hoststatus.VendordataOff:
		return ui.Muted("off · new VMs will not trust the SSH CA" + svc)
	}
	return ui.Warn(c.State) + ui.Muted(" · "+strings.Join(caTrustOdd(c), ", "))
}

// caTrustOdd names the hosts that are not simply on, worst first.
func caTrustOdd(c openstack.CATrust) []string {
	out := make([]string, 0, len(c.Hosts))
	for host, state := range c.Hosts {
		if state != hoststatus.VendordataOn {
			out = append(out, host+"="+state)
		}
	}
	sort.Strings(out)
	return out
}

// renderAnomalies puts everything worth a second look in one block. Scattered
// through the sections above they are each a footnote; together they are the
// answer to "what is wrong with this farm".
func renderAnomalies(w io.Writer, anomalies []openstack.Anomaly, state string) {
	if len(anomalies) == 0 {
		return
	}
	fmt.Fprintf(w, "\n  %s\n", ui.Value("anomalies"))
	for _, an := range anomalies {
		mark := ui.Warn("!")
		if an.Severity == openstack.SeverityError {
			mark = ui.Fail("!!")
		}
		detail := an.Detail
		if an.Expected {
			// Still shown — a farm declared broken has to be able to say what
			// is broken about it — but marked as following from the
			// declaration rather than as news.
			mark = ui.Muted("·")
			detail += ui.Muted(" (expected while " + state + ")")
		}
		fmt.Fprintf(w, "  %s %s  %s\n", mark, ui.PadRight(an.Subject, 20), ui.Muted(detail))
	}
}

// declaredStateLine renders what an operator said about the farm, and how long
// ago. A farm broken for an hour and one broken for a month are different
// situations and the word alone does not say which.
func declaredStateLine(a openstack.Assessment, now time.Time) string {
	if a.State == "" || a.State == store.StateActive {
		return ""
	}
	s := stateCell(a.State)
	if a.StateSince != nil {
		s += ui.Muted(" for " + strutil.CompactDuration(now.Sub(*a.StateSince)))
	}
	if a.StateNote != "" {
		s += ui.Muted(" — " + a.StateNote)
	}
	return s
}

func vmLine(a openstack.Assessment) string {
	s := fmt.Sprintf("%d", a.Architecture.VMs)
	if a.Health.VMsMissing > 0 {
		s += " " + ui.Warn(fmt.Sprintf("(+%d no longer listed)", a.Health.VMsMissing))
	}
	return s
}

// reconcileLine says when this farm's membership was last settled, and why not
// if it was not.
//
// Without it "local-only" cannot be read. It could mean the control plane
// disagreed an hour ago, or that nothing has asked in three weeks — and those
// call for opposite responses.
func reconcileLine(f openstack.Freshness, now time.Time) string {
	if f.LastAttempt == nil {
		return ui.Warn("never — no run has been recorded for this deployment")
	}
	if f.LastSuccess == nil {
		return ui.Fail("never succeeded") + " · " +
			ui.Muted("last tried "+strutil.CompactDuration(now.Sub(*f.LastAttempt))+" ago: "+ui.Truncate(f.Error, 60))
	}
	s := strutil.CompactDuration(now.Sub(*f.LastSuccess)) + " ago"
	if f.Stale {
		s = ui.Warn(s)
	}
	if !f.Complete {
		s += " " + ui.Warn("(partial answer — nothing was demoted)")
	}
	if f.Error != "" {
		s += " · " + ui.Fail("failing since "+strutil.CompactDuration(now.Sub(*f.LastAttempt))+" ago: "+ui.Truncate(f.Error, 50))
	}
	return s
}

// releaseLine says in one line whether the farm is on one release or drifting —
// which is the question a farm view usually exists to answer.
func releaseLine(v openstack.Versions) string {
	if !v.Drifting {
		for r, n := range v.ByRelease {
			return fmt.Sprintf("%s %s", r, ui.Muted(fmt.Sprintf("(all %d)", n)))
		}
		return ui.Muted("-")
	}
	keys := make([]string, 0, len(v.ByRelease))
	for r := range v.ByRelease {
		keys = append(keys, r)
	}
	// Largest first: the line reads "mostly X, with stragglers on Y".
	sort.Slice(keys, func(i, j int) bool {
		if v.ByRelease[keys[i]] != v.ByRelease[keys[j]] {
			return v.ByRelease[keys[i]] > v.ByRelease[keys[j]]
		}
		return keys[i] < keys[j]
	})
	parts := make([]string, 0, len(keys))
	for _, r := range keys {
		parts = append(parts, fmt.Sprintf("%s ×%d", r, v.ByRelease[r]))
	}
	return ui.Warn("drift: " + strings.Join(parts, " · "))
}

// allRepeats returns the compact membership line for a section whose every
// host was already shown, and "" when the section introduces anyone new.
func allRepeats(sec openstack.RoleSection) string {
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
