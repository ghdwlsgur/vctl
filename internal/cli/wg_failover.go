package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/access"
	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The Incheon side of the standby hub. Each remote that dials two hubs runs
// wg-standby-failover.sh from a 30 s systemd timer and decides for itself, from
// its own handshake ages, which peer carries the transit networks. That design
// is deliberate — no watcher VM, no Seoul→Incheon control path, no extra
// credential — but it leaves an operator with nothing to look at: the answer
// lives in four separate boxes.
//
// These commands are that view, and the override. They add no decision logic;
// the remotes stay authoritative. vctl only asks each one what it sees and,
// when told to, runs the same --failover/--failback/hold the script already
// exposes. Nothing here is a second place where failover policy is written.
const (
	failoverScript = "/usr/local/sbin/wg-standby-failover.sh"
	// Printed by the probe when a host has no failover agent, so a fan-out over
	// the whole inventory reports "not installed" instead of an error per host —
	// the same courtesy `wg sync` extends to hosts without WireGuard.
	failoverAbsentMark = "__vctl_no_failover__"
	// The script reports a handshake that never happened as this many seconds.
	failoverNeverAge = 999999
)

func wgFailoverCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "failover",
		Short: "Which hub each remote is using, and move it between them",
		Long: `failover inspects and drives the standby-hub switch that each WireGuard
remote runs for itself (wg-standby-failover.sh, on a 30s systemd timer).

A remote dials two hubs on one interface. Whichever peer holds the transit
networks in its allowed-ips is the one carrying traffic; the timer moves them to
the standby when the primary goes quiet and back once it has been healthy again
for a while. vctl neither decides nor duplicates that — it reads each remote's
own verdict and can force the move the script already supports.

  vctl wg failover status --all        what every remote is using right now
  vctl wg failover to-standby <host>   force this remote onto the standby hub
  vctl wg failover to-primary <host>   force it back
  vctl wg failover hold <host>         freeze automatic switching (--clear to resume)`,
	}
	cmd.AddCommand(
		wgFailoverStatusCmd(env),
		wgFailoverSwitchCmd(env, "to-standby", "--failover", "onto the standby hub"),
		wgFailoverSwitchCmd(env, "to-primary", "--failback", "back onto the primary hub"),
		wgFailoverHoldCmd(env),
	)
	return cmd
}

// wgFailoverStatusCmd reads each remote's own verdict. Read class: it changes
// nothing, though it does open an audited SSH connection like `wg monitor`.
func wgFailoverStatusCmd(env cmdkit.Env) *cobra.Command {
	var opts wgFailoverOptions
	cmd := &cobra.Command{
		Use:   "status [host...]",
		Short: "Which hub each remote is carrying transit on, with handshake ages",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWGFailoverStatus(cmd, env, args, opts)
		},
	}
	bindFailoverFlags(cmd, env, &opts)
	cmd.Flags().BoolVar(&opts.asJSON, "json", false, "machine-readable output")
	return cmdkit.SupportsStructuredOutput(cmdkit.Gate(cmd, "wg"))
}

// wgFailoverSwitchCmd builds to-standby/to-primary, which differ only in the
// flag they hand the remote script.
func wgFailoverSwitchCmd(env cmdkit.Env, use, scriptFlag, where string) *cobra.Command {
	var opts wgFailoverOptions
	cmd := &cobra.Command{
		Use:   use + " <host...>",
		Short: "Force a remote's transit networks " + where,
		Long: `Moves the transit networks between the two hub peers now, without waiting
for the timer's own judgement. The timer keeps running afterwards and may move
them back on its next tick — pair this with 'hold' when the override has to
stick.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWGFailoverAction(cmd, env, args, opts, scriptFlag)
		},
	}
	bindFailoverFlags(cmd, env, &opts)
	return cmdkit.Gate(cmd, "wg-failover")
}

func wgFailoverHoldCmd(env cmdkit.Env) *cobra.Command {
	var opts wgFailoverOptions
	cmd := &cobra.Command{
		Use:   "hold <host...>",
		Short: "Freeze a remote's automatic switching (--clear to resume)",
		Long: `hold drops the script's hold file, after which its timer evaluates and does
nothing. Use it while working on a hub so a maintenance window is not read as an
outage. --clear removes the file and automatic switching resumes on the next
tick.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWGFailoverHold(cmd, env, args, opts)
		},
	}
	bindFailoverFlags(cmd, env, &opts)
	cmd.Flags().BoolVar(&opts.clear, "clear", false, "remove the hold and let the timer decide again")
	return cmdkit.Gate(cmd, "wg-failover")
}

// wgFailoverOptions is the flag set shared by the failover subcommands.
type wgFailoverOptions struct {
	all        bool
	dc         string
	asJSON     bool
	clear      bool
	timeoutSec int
}

func bindFailoverFlags(cmd *cobra.Command, env cmdkit.Env, opts *wgFailoverOptions) {
	f := cmd.Flags()
	f.BoolVar(&opts.all, "all", false, "every inventory host; those without the failover agent are reported, not probed")
	f.StringVar(&opts.dc, "dc", "", "restrict to a DC (with no host args)")
	f.IntVar(&opts.timeoutSec, "timeout", 20, "per-host SSH command timeout (seconds)")
	cmd.ValidArgsFunction = cmdkit.CompleteInventoryHost(env)
}

// failoverStatus is one remote's answer, parsed from the script's --status.
type failoverStatus struct {
	Host       string `json:"host"`
	Installed  bool   `json:"installed"`
	Iface      string `json:"iface,omitempty"`
	Active     string `json:"active,omitempty"` // primary | standby | unknown
	PrimaryAge int    `json:"primary_handshake_age_seconds,omitempty"`
	StandbyAge int    `json:"standby_handshake_age_seconds,omitempty"`
	DownAfter  int    `json:"down_after_seconds,omitempty"`
	UpFor      int    `json:"up_for_seconds,omitempty"`
	Hold       bool   `json:"hold"`
	Since      string `json:"active_since,omitempty"`
	// Decision is the script's own verdict for right now, from --dry-run. It is
	// the only thing that explains a row: "standby" in the table says where
	// traffic is, this says why it is still there.
	Decision string `json:"decision,omitempty"`
	Err      string `json:"error,omitempty"`
}

// parseFailoverStatus reads the script's --status output. Kept pure so the
// shape of that output is pinned by a test rather than by a live remote.
func parseFailoverStatus(host, out string) failoverStatus {
	s := failoverStatus{Host: host, Installed: true}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.Contains(line, failoverAbsentMark):
			return failoverStatus{Host: host}
		case strings.HasPrefix(line, "HOLD:"):
			s.Hold = true
		case strings.HasPrefix(line, "state:"):
			s.Since = strings.TrimSpace(fieldAfter(line, "since="))
		case strings.HasPrefix(line, "decision:"):
			s.Decision = strings.TrimSpace(strings.TrimPrefix(line, "decision:"))
		default:
			applyFailoverFields(&s, line)
		}
	}
	if s.Iface == "" && s.Active == "" {
		s.Err = "unrecognised status output"
	}
	return s
}

// applyFailoverFields reads the script's single key=value status line.
func applyFailoverFields(s *failoverStatus, line string) {
	for _, kv := range strings.Fields(line) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "iface":
			s.Iface = v
		case "active":
			s.Active = v
		case "primary_hs_age":
			s.PrimaryAge = parseSeconds(v)
		case "standby_hs_age":
			s.StandbyAge = parseSeconds(v)
		case "down_after":
			s.DownAfter = parseSeconds(v)
		case "up_for":
			s.UpFor = parseSeconds(v)
		}
	}
}

// fieldAfter returns the whitespace-delimited value following key in line.
func fieldAfter(line, key string) string {
	_, rest, ok := strings.Cut(line, key)
	if !ok {
		return ""
	}
	if i := strings.Index(rest, " primary_fresh_since="); i >= 0 {
		return rest[:i]
	}
	return rest
}

func parseSeconds(v string) int {
	n, err := strconv.Atoi(strings.TrimSuffix(v, "s"))
	if err != nil {
		return 0
	}
	return n
}

// age renders a handshake age, naming the sentinel the script uses for "never".
func (s failoverStatus) age(seconds int) string {
	if seconds >= failoverNeverAge {
		return "never"
	}
	return (time.Duration(seconds) * time.Second).String()
}

// healthy reports whether this remote is where it should be: on the primary,
// with both hubs answering and no operator hold.
func (s failoverStatus) healthy() bool {
	return s.Installed && s.Err == "" && s.Active == "primary" &&
		!s.Hold && s.PrimaryAge < failoverNeverAge && s.StandbyAge < failoverNeverAge
}

// failoverReply pairs one remote with what it said.
type failoverReply struct {
	Host   string
	Stdout string
	Err    error
}

// failoverProbe asks every target the same question at once. The command is
// built per host because escalation depends on the login user: the remotes are
// a mix of root and sudo logins, exactly as remote-failover/deploy.sh found
// them.
func failoverProbe(ctx context.Context, env cmdkit.Env, args []string, opts wgFailoverOptions,
	body func(sudo string) string) ([]failoverReply, error) {
	a, err := env.App()
	if err != nil {
		return nil, err
	}
	st, err := a.OpenStore(ctx, app.PurposeInventoryRead)
	if err != nil {
		return nil, err
	}
	defer st.Close()

	hosts, err := wgTargetHosts(ctx, st, args, opts.dc, opts.all)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no target hosts: name the remotes, or pass --all/--dc")
	}

	conn := cmdkit.NewConnector(a)
	timeout := time.Duration(opts.timeoutSec) * time.Second
	run := func(ctx context.Context, sv *store.Server) (string, error) {
		tgt, err := access.BuildTarget(ctx, st, sv, a.Cfg.SSHDirectFirst)
		if err != nil {
			return "", fmt.Errorf("build target: %w", err)
		}
		res, err := conn.Execute(ctx,
			access.Request{Target: tgt, HostKey: access.HostKeyAcceptNew},
			body(sudoFor(tgt.User)), timeout)
		return res.Stdout, err
	}
	return fanOutHosts(ctx, hosts, 6, run), nil
}

// sudoFor returns the escalation prefix a login user needs. -n so a host with
// no passwordless sudo fails loudly instead of hanging on a prompt nobody can
// answer.
func sudoFor(user string) string {
	if user == "root" {
		return ""
	}
	return "sudo -n "
}

// fanOutHosts runs one command across hosts with bounded concurrency, keeping
// the caller's order so a table does not reshuffle between runs.
func fanOutHosts(ctx context.Context, hosts []store.Server, limit int,
	run func(context.Context, *store.Server) (string, error)) []failoverReply {
	out := make([]failoverReply, len(hosts))
	sem := make(chan struct{}, limit)
	done := make(chan int, len(hosts))
	for i := range hosts {
		go func(i int) {
			sem <- struct{}{}
			defer func() { <-sem; done <- i }()
			stdout, err := run(ctx, &hosts[i])
			out[i] = failoverReply{Host: hosts[i].Hostname, Stdout: stdout, Err: err}
		}(i)
	}
	for range hosts {
		<-done
	}
	return out
}

// failoverShell wraps a script invocation so a host without the agent answers
// with the sentinel instead of a shell error.
func failoverShell(sudo, scriptArgs string) string {
	return fmt.Sprintf("if [ -x %s ]; then %s%s %s; else echo %s; fi",
		failoverScript, sudo, failoverScript, scriptArgs, failoverAbsentMark)
}

func runWGFailoverStatus(cmd *cobra.Command, env cmdkit.Env, args []string, opts wgFailoverOptions) error {
	format, err := cmdkit.CommandOutput(cmd, opts.asJSON)
	if err != nil {
		return err
	}
	replies, err := failoverProbe(cmd.Context(), env, args, opts,
		func(sudo string) string {
			return failoverShell(sudo, "--status") + "; " + failoverShell(sudo, "--dry-run")
		})
	if err != nil {
		return err
	}
	out := make([]failoverStatus, 0, len(replies))
	for _, r := range replies {
		out = append(out, statusFromReply(r))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	if format != cmdkit.OutputTable {
		return cmdkit.WriteStructured(format, out)
	}
	return printFailoverStatuses(out)
}

// statusFromReply turns one remote's answer into a row, keeping a failed probe
// as a row rather than an error: with --all, one unreachable host must not hide
// the other three.
func statusFromReply(r failoverReply) failoverStatus {
	if r.Err != nil && strings.TrimSpace(r.Stdout) == "" {
		return failoverStatus{Host: r.Host, Err: r.Err.Error()}
	}
	s := parseFailoverStatus(r.Host, r.Stdout)
	if r.Err != nil && s.Err == "" {
		s.Err = r.Err.Error()
	}
	return s
}

// printFailoverStatuses renders one row per remote. The verdict column is the
// point of the table: "primary" everywhere is the resting state, any "standby"
// means a hub is being worked around right now.
func printFailoverStatuses(all []failoverStatus) error {
	rows := make([][]string, 0, len(all))
	var tally failoverTally
	for _, s := range all {
		tally.add(s)
		rows = append(rows, failoverRow(s))
	}
	ui.Section(os.Stdout, "standby-hub failover")
	if err := ui.Table(os.Stdout,
		[]string{"remote", "iface", "carrying", "primary hs", "standby hs", "hold"}, rows); err != nil {
		return err
	}
	explainFailoverExceptions(all)
	return tally.report()
}

// explainFailoverExceptions prints the remote's own reasoning for every row
// that is not at rest. A fleet where everything sits on the primary stays
// quiet; the one row that does not is the one worth reading about.
func explainFailoverExceptions(all []failoverStatus) {
	for _, s := range all {
		if s.Decision == "" || s.healthy() {
			continue
		}
		ui.Infof(os.Stdout, "%s: %s", s.Host, s.Decision)
	}
}

// failoverTally counts what the table is about to show, so the summary can name
// the exceptional row instead of leaving it to be spotted.
type failoverTally struct {
	total, ready, onStandby, absent, failed, held, uncovered int
}

func (t *failoverTally) add(s failoverStatus) {
	t.total++
	switch {
	case s.Err != "":
		t.failed++
	case !s.Installed:
		t.absent++
	case s.Active == "standby":
		t.onStandby++
	}
	if s.healthy() {
		t.ready++
	}
	if s.Hold {
		t.held++
	}
	// A remote whose standby hub has never answered cannot fail over: the
	// script requires a fresh standby handshake before it will move anything,
	// so this one would sit out an outage rather than switch. It looks healthy
	// in every other column, which is exactly why it needs naming.
	if s.Installed && s.Err == "" && s.StandbyAge >= failoverNeverAge {
		t.uncovered++
	}
}

func (t failoverTally) report() error {
	ui.KVs(os.Stderr, []ui.KV{
		{Key: "Remotes", Value: strconv.Itoa(t.total)},
		{Key: "Ready on the primary hub", Value: strconv.Itoa(t.ready), State: ui.StateOK},
		{Key: "On the standby hub", Value: strconv.Itoa(t.onStandby), State: ui.StateWarn},
		{Key: "Held (no auto switching)", Value: strconv.Itoa(t.held), State: ui.StateWarn},
		{Key: "Standby never handshook", Value: strconv.Itoa(t.uncovered), State: ui.StateWarn},
		{Key: "No failover agent", Value: strconv.Itoa(t.absent), State: ui.StateWarn},
		{Key: "Unreachable", Value: strconv.Itoa(t.failed), State: ui.StateFail},
	})
	if t.uncovered > 0 {
		ui.Warnf(os.Stderr, "%d remote(s) have never heard from the standby hub — they would ride out a primary outage instead of switching, because the script will not move transit onto a peer that is not answering", t.uncovered)
	}
	if t.failed > 0 {
		return fmt.Errorf("%d remote(s) did not answer", t.failed)
	}
	return nil
}

func failoverRow(s failoverStatus) []string {
	switch {
	case s.Err != "":
		return []string{s.Host, "-", "unreachable", "-", "-", "-"}
	case !s.Installed:
		return []string{s.Host, "-", "no agent", "-", "-", "-"}
	}
	hold := "-"
	if s.Hold {
		hold = "HELD"
	}
	return []string{
		s.Host, s.Iface, s.Active,
		s.age(s.PrimaryAge), s.age(s.StandbyAge), hold,
	}
}

// runWGFailoverAction forces the move on each named remote. The script is
// idempotent — asked to go somewhere it already is, it says so and changes
// nothing — so a repeated command is safe.
func runWGFailoverAction(cmd *cobra.Command, env cmdkit.Env, args []string,
	opts wgFailoverOptions, scriptFlag string) error {
	replies, err := failoverProbe(cmd.Context(), env, args, opts,
		func(sudo string) string { return failoverShell(sudo, scriptFlag) })
	if err != nil {
		return err
	}
	return reportFailoverActions(replies, "switch")
}

// runWGFailoverHold sets or clears the hold file. It sources the config first
// so a remote that overrides HOLD_FILE is still honoured — guessing the default
// path would silently hold nothing.
func runWGFailoverHold(cmd *cobra.Command, env cmdkit.Env, args []string, opts wgFailoverOptions) error {
	op, verb := "touch", "hold"
	if opts.clear {
		op, verb = "rm -f", "release"
	}
	body := func(sudo string) string {
		return fmt.Sprintf(
			"if [ -x %s ]; then %ssh -c '. /etc/wireguard/failover.conf 2>/dev/null; %s \"${HOLD_FILE:-/etc/wireguard/failover.hold}\" && echo %s ok'; else echo %s; fi",
			failoverScript, sudo, op, verb, failoverAbsentMark)
	}
	replies, err := failoverProbe(cmd.Context(), env, args, opts, body)
	if err != nil {
		return err
	}
	return reportFailoverActions(replies, verb)
}

// reportFailoverActions prints what each remote did and fails the command if
// any of them did not.
func reportFailoverActions(replies []failoverReply, what string) error {
	bad := 0
	for _, r := range replies {
		out := strings.TrimSpace(r.Stdout)
		switch {
		case r.Err != nil:
			bad++
			ui.Warnf(os.Stderr, "%s: %v", r.Host, r.Err)
		case strings.Contains(out, failoverAbsentMark):
			bad++
			ui.Warnf(os.Stderr, "%s: no failover agent installed (%s)", r.Host, failoverScript)
		default:
			ui.Successf(os.Stdout, "%s: %s", r.Host, firstLine(out))
		}
	}
	if bad > 0 {
		return fmt.Errorf("%s failed on %d remote(s)", what, bad)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
