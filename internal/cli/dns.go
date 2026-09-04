package cli

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	osuser "os/user"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/dnshosts"
	"github.com/ghdwlsgur/vctl/internal/gitlabapi"
	"github.com/ghdwlsgur/vctl/internal/kubeapi"
	"github.com/ghdwlsgur/vctl/internal/strutil"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// The fleet's DNS records live in one CoreDNS hosts ConfigMap, and the same
// content lives in the IaC repo as configmap-hosts.yaml. A change has to land
// in both, in that order: the repo is the source of truth an ArgoCD sync
// would reassert — a record written only to the cluster is undone by the next
// sync — and the live ConfigMap is what makes the record answer now instead
// of whenever somebody syncs. dnshosts owns keeping the two byte-compatible.
//
// Reads come from the live ConfigMap alone: it is what CoreDNS is actually
// serving, which is the question a lookup asks.
const (
	dnsNamespace  = dnshosts.Namespace
	dnsHostsCM    = dnshosts.ConfigMapName
	dnsCorefileCM = "coredns-corefile"
	dnsRepoFile   = "configmap-hosts.yaml"
	dnsRepoBranch = "main"
	dnsStampAnn   = "vctl.sre.local/last-change"
	// dnsWriteAttempts bounds the optimistic-concurrency retry on each side:
	// a conflict means another writer landed between the read and the write,
	// and the fix is to re-read and reapply — but not forever.
	dnsWriteAttempts = 3
	dnsVerifyEvery   = 3 * time.Second
	// Propagation is kubelet's ConfigMap sync (up to a minute) plus the hosts
	// plugin's re-read; two minutes is patient enough to be a verdict.
	dnsVerifyFor = 2 * time.Minute
)

func dnsCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns [name]",
		Short: "Query and manage the fleet's DNS records",
		Long: `dns reads and edits the records the fleet's CoreDNS answers with.

  vctl dns                          every record, grouped by zone
  vctl dns gitlab                   records matching a name or address
  vctl dns add <hostname> <ip>      register (zone inferred from the name)
  vctl dns rm <hostname>            deregister

A change is committed to the IaC repo first — the repo is what an ArgoCD sync
reasserts — then patched into the live ConfigMap so it answers immediately,
then verified with a real query against the fleet resolver.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithApp(func(a *app.App) error {
				return runDNSList(cmd.Context(), a, argOr(args, 0))
			})
		},
	}
	cmd.AddCommand(cmdkit.Gate(dnsAddCmd(env), "dns"))
	cmd.AddCommand(cmdkit.Gate(dnsRmCmd(env), "dns"))
	// The listing is a read-only view of a resource whose grant name is
	// mutate-classed, so it self-gates as a read view — the same shape `vctl
	// ip` uses for the ledger that a granted `ip set` writes. This keeps login
	// enforcement on the gate rather than only in openDNS's in-body call.
	return cmdkit.GateReadView(cmd, "dns")
}

func argOr(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// dnsRepo and dnsCluster are the two places a record lives, as the write path
// sees them: the IaC repository and the cluster serving the ConfigMap. In
// production they are gitlabapi.Client and kubeapi.Client. They are
// interfaces so the ordering and retry logic in dnsMutate can be run against
// fakes — the races it guards against cannot be reproduced any other way.
type dnsRepo interface {
	GetFile(ctx context.Context, project, path, ref string) (*gitlabapi.File, error)
	UpdateFile(ctx context.Context, project, path, branch, content, message, lastCommitID string) error
}

type dnsCluster interface {
	GetConfigMap(ctx context.Context, namespace, name string) (*kubeapi.ConfigMap, error)
	PatchConfigMapData(ctx context.Context, namespace, name, resourceVersion string, data, annotations map[string]string) error
}

// dnsSession is everything one dns command needs, opened once: the cluster
// client, and — for writes — the repo client.
type dnsSession struct {
	kube dnsCluster
	git  dnsRepo
	cfg  *config.Config
}

func openDNS(ctx context.Context, a *app.App, forWrite bool) (*dnsSession, error) {
	if err := a.EnsureLogin(ctx); err != nil {
		return nil, err
	}
	sec, err := a.Vault.ReadKV(ctx, a.Cfg.DNSKubeKVPath)
	if err != nil {
		return nil, fmt.Errorf("no DNS credentials at %s (%w) — see the coredns repo's vctl-dns-rbac.yaml", a.Cfg.DNSKubeKVPath, err)
	}
	kube, err := kubeapi.New(sec["server"], sec["token"], []byte(sec["ca"]), sec["server_name"])
	if err != nil {
		return nil, err
	}
	s := &dnsSession{kube: kube, cfg: a.Cfg}
	if !forWrite {
		return s, nil
	}
	tok, err := a.Vault.ReadKV(ctx, a.Cfg.DNSGitTokenKVPath)
	if err != nil {
		return nil, fmt.Errorf("no GitLab token at %s (%w) — a DNS change must land in the IaC repo", a.Cfg.DNSGitTokenKVPath, err)
	}
	git, err := gitlabapi.New(a.Cfg.DNSGitBase, tok["token"], config.SRERootCA)
	if err != nil {
		return nil, err
	}
	s.git = git
	return s, nil
}

// runDNSList prints the records, grouped by zone file — filtered when a name
// or address fragment was given, with a live resolver answer when the filter
// is an exact hostname.
func runDNSList(ctx context.Context, a *app.App, filter string) error {
	s, err := openDNS(ctx, a, false)
	if err != nil {
		return err
	}
	cm, err := s.kube.GetConfigMap(ctx, dnsNamespace, dnsHostsCM)
	if err != nil {
		return err
	}
	w := os.Stdout
	shown := 0
	for _, key := range dnshosts.OrderedKeys(cm.Data) {
		var cells [][]string
		for _, r := range dnshosts.Parse(cm.Data[key]) {
			names := strings.Join(r.Hostnames, " ")
			if filter != "" && !strings.Contains(names, filter) && !strings.Contains(r.IP, filter) {
				continue
			}
			cells = append(cells, []string{r.IP, names})
		}
		if len(cells) == 0 {
			continue
		}
		shown += len(cells)
		fmt.Fprintf(w, "\n%s\n", ui.GroupHeading(strings.TrimSuffix(key, ".hosts"), fmt.Sprintf("%d records", len(cells))))
		widths := ui.ColumnWidths(cells)
		for _, c := range cells {
			fmt.Fprintln(w, "  "+ui.GridRow([]string{ui.Muted(c[0]), c[1]}, widths))
		}
	}
	if shown == 0 {
		ui.Infof(w, "no records match %q.", filter)
	}
	// An exact name also gets the live answer — what the resolver actually
	// says is the fact a lookup is usually after, and it includes the
	// Corefile's template wildcards, which the hosts files cannot show.
	if filter != "" && !strings.ContainsAny(filter, " /") {
		if addrs, err := dnsResolveVia(ctx, a.Cfg.DNSResolver, filter); err == nil && len(addrs) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintf(w, "  %s\n", ui.Muted(fmt.Sprintf("live: %s → %s (asked %s)", filter, strings.Join(addrs, ", "), a.Cfg.DNSResolver)))
		}
	}
	return nil
}

func dnsAddCmd(env cmdkit.Env) *cobra.Command {
	var zone string
	cmd := &cobra.Command{
		Use:   "add <hostname> <ip>",
		Short: "Register a DNS record (IaC commit + live ConfigMap + verify)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithApp(func(a *app.App) error {
				return runDNSAdd(cmd.Context(), a, args[0], args[1], zone)
			})
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "zone to file the record under (default: inferred from the hostname)")
	return cmd
}

func runDNSAdd(ctx context.Context, a *app.App, hostname, ip, zoneFlag string) error {
	s, err := openDNS(ctx, a, true)
	if err != nil {
		return err
	}
	ip = dnsCanonicalIP(ip)
	if err := dnsAdd(ctx, s, hostname, ip, zoneFlag); err != nil {
		return err
	}
	// Every successful add is verified — the one that committed and the one
	// that only reasserted the cluster alike. OK on screen means the record
	// answers, not that an API call succeeded.
	return dnsVerifyAnswers(ctx, s.cfg.DNSResolver, hostname, ip)
}

// dnsCanonicalIP is the one spelling of an address the stored line, the
// duplicate check, and the post-write verification all compare. dnshosts.Add
// canonicalizes what it stores; this makes the value the command reports and
// verifies match it. A string that is not an address is left for Add to
// reject with its own message.
func dnsCanonicalIP(ip string) string {
	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.String()
	}
	return ip
}

// dnsAdd files hostname → ip in the zone the Corefile serves it from, through
// the repo and onto the cluster. It is idempotent in the useful direction: a
// record already present exactly as asked is not committed again, but the
// cluster is still reasserted from the repo — the repo being right does not
// make the cluster right, and "already registered" from a resolver that does
// not answer is the state this command exists to end.
func dnsAdd(ctx context.Context, s *dnsSession, hostname, ip, zoneFlag string) error {
	// Zone bindings come from the live Corefile, read once: the edit below runs
	// on every retry, and the Corefile does not change between attempts.
	bindings, err := s.zoneBindings(ctx)
	if err != nil {
		return err
	}
	return dnsMutate(ctx, s, "add "+hostname+" "+ip, func(data map[string]string) error {
		key, zone, err := dnsZoneKey(bindings, data, hostname, zoneFlag)
		if err != nil {
			return err
		}
		// Every zone file, in sorted order, so the verdict is the same on
		// every run: the same name answering from two files is a coin flip
		// per query, and a name already present exactly as asked is a
		// no-op — but a conflict anywhere outranks a match anywhere.
		var matchKey string
		for _, k := range slices.Sorted(maps.Keys(data)) {
			if have, ok := dnshosts.Lookup(data[k], hostname); ok {
				if have != ip {
					return fmt.Errorf("%s already answers with %s (in %s); remove it first", hostname, have, k)
				}
				matchKey = k
			}
		}
		if matchKey != "" {
			ui.Infof(os.Stderr, "%s → %s is already registered in %s.", hostname, ip, matchKey)
			return errDNSNoChange
		}
		next, err := dnshosts.Add(data[key], ip, hostname)
		if err != nil {
			return err
		}
		ui.Infof(os.Stderr, "filing %s → %s under %s (zone %s)", hostname, ip, key, zone)
		data[key] = next
		return nil
	})
}

func dnsRmCmd(env cmdkit.Env) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm <hostname>",
		Short: "Deregister a DNS record (IaC commit + live ConfigMap)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return env.WithApp(func(a *app.App) error {
				return runDNSRm(cmd.Context(), a, args[0])
			})
		},
	}
	return cmd
}

func runDNSRm(ctx context.Context, a *app.App, hostname string) error {
	s, err := openDNS(ctx, a, true)
	if err != nil {
		return err
	}
	return dnsRm(ctx, s, hostname)
}

// dnsRm deregisters hostname from every zone file that carries it. Add keeps
// a name to one file, but a hand edit need not have, and "deregistered" has
// to mean the name no longer answers — not that one of its lines is gone.
func dnsRm(ctx context.Context, s *dnsSession, hostname string) error {
	return dnsMutate(ctx, s, "rm "+hostname, func(data map[string]string) error {
		removed := 0
		for _, key := range slices.Sorted(maps.Keys(data)) {
			next, ok := dnshosts.Remove(data[key], hostname)
			if !ok {
				continue
			}
			ip, _ := dnshosts.Lookup(data[key], hostname)
			ui.Infof(os.Stderr, "removing %s (was %s, in %s)", hostname, ip, key)
			data[key] = next
			removed++
		}
		if removed == 0 {
			return fmt.Errorf("%s is not registered in any zone file (Corefile template wildcards are not records — see the Corefile)", hostname)
		}
		return nil
	})
}

// errDNSNoChange is an edit's way of saying the repo already holds what was
// asked. dnsMutate then skips the commit but still projects the repo onto
// the cluster: the caller wanted the record to answer, and a repo that is
// already right says nothing about whether the cluster is.
var errDNSNoChange = errors.New("no change")

// dnsMutate is the one write path, and the repo is its source of truth. The
// edit is applied to what the IaC repo holds — not to the live ConfigMap — so
// the record is committed to the repo first and the cluster is a projection of
// it. That order is not a preference: an ArgoCD sync reasserts the repo, so a
// record that reached the cluster but not the repo is removed by the next
// sync. Committing first means a crash between the two writes leaves the repo
// ahead, which the sync then repairs in the safe direction.
//
// The projection reads the repo again rather than reusing what this process
// committed: the cluster is made to match the repo's HEAD, whatever that is
// by then. Two writers landing commits back to back each project HEAD, so
// whichever patches last leaves the cluster carrying both records. Projecting
// a local snapshot instead would let the earlier writer's patch — with a fresh
// resourceVersion, so no conflict — silently revert the later writer's record
// until the next sync.
func dnsMutate(ctx context.Context, s *dnsSession, action string, edit func(map[string]string) error) error {
	data, committed, err := dnsCommit(ctx, s, action, edit)
	if err != nil {
		return err
	}
	if err := dnsProject(ctx, s, action, dnshosts.RecordCount(data)); err != nil {
		return err
	}
	if committed {
		ui.Successf(os.Stderr, "recorded in the IaC repo and the live ConfigMap.")
	} else {
		ui.Successf(os.Stderr, "the IaC repo already had it; reasserted the live ConfigMap.")
	}
	return nil
}

// dnsCommit applies edit to the repo file and commits the result, retrying
// on a conflict by re-reading and re-applying — the edit runs against the
// repo's own content on every attempt, so the last_commit_id precondition
// guards both the version and the value, and a retry lands on top of the
// concurrent writer's work rather than over it. Returns the repo state as
// it stands after the call, and whether a commit was made — false means the
// repo already held the edited state.
func dnsCommit(ctx context.Context, s *dnsSession, action string, edit func(map[string]string) error) (data map[string]string, committed bool, err error) {
	msg := fmt.Sprintf("dns: %s (vctl by %s)", action, dnsActor())
	for attempt := 1; ; attempt++ {
		file, err := s.git.GetFile(ctx, s.cfg.DNSGitProject, dnsRepoFile, dnsRepoBranch)
		if err != nil {
			return nil, false, fmt.Errorf("read %s from the IaC repo: %w", dnsRepoFile, err)
		}
		data, err := dnshosts.ParseConfigMapYAML(file.Content)
		if err != nil {
			return nil, false, fmt.Errorf("the IaC repo's %s is not the hosts ConfigMap vctl edits (%w) — fix the file first", dnsRepoFile, err)
		}
		if err := edit(data); err != nil {
			if errors.Is(err, errDNSNoChange) {
				return data, false, nil
			}
			return nil, false, err
		}
		rendered := dnshosts.RenderConfigMapYAML(data)
		if rendered == file.Content {
			return data, false, nil
		}
		err = s.git.UpdateFile(ctx, s.cfg.DNSGitProject, dnsRepoFile, dnsRepoBranch, rendered, msg, file.LastCommitID)
		if err == nil {
			return data, true, nil
		}
		if errors.Is(err, gitlabapi.ErrConflict) && attempt < dnsWriteAttempts {
			ui.Warnf(os.Stderr, "the repo file moved; re-reading and retrying (%d/%d)", attempt, dnsWriteAttempts)
			continue
		}
		return nil, false, fmt.Errorf("commit to the IaC repo: %w", err)
	}
}

// dnsProject makes the live ConfigMap match the repo's HEAD so the records
// answer now instead of at the next sync. wantRecords is how many records the
// repo held when this process finished committing; it refuses to project if
// HEAD has since gone to none. A repo that had records a moment ago and has
// none now was emptied by something else in between — a bad hand edit, a
// broken sync — and the cluster must keep answering until it is fixed. A
// deregistration this process made itself is not that: it removed what it
// was asked to, and wantRecords already reflects it.
func dnsProject(ctx context.Context, s *dnsSession, action string, wantRecords int) error {
	ann := map[string]string{
		dnsStampAnn: fmt.Sprintf("%s %s %s", time.Now().UTC().Format(time.RFC3339), dnsActor(), action),
	}
	for attempt := 1; ; attempt++ {
		file, err := s.git.GetFile(ctx, s.cfg.DNSGitProject, dnsRepoFile, dnsRepoBranch)
		if err != nil {
			return fmt.Errorf("the IaC repo holds the change, but re-reading it for the cluster failed (%w) — the next ArgoCD sync (manual) will apply it", err)
		}
		data, err := dnshosts.ParseConfigMapYAML(file.Content)
		if err != nil {
			return fmt.Errorf("the IaC repo holds the change, but its %s no longer reads as the hosts ConfigMap (%w) — the cluster was left as it was", dnsRepoFile, err)
		}
		cm, err := s.kube.GetConfigMap(ctx, dnsNamespace, dnsHostsCM)
		if err != nil {
			return fmt.Errorf("the IaC repo holds the change, but reading the live ConfigMap failed (%w) — the next ArgoCD sync (manual) will apply it", err)
		}
		if dnshosts.RecordCount(data) == 0 && wantRecords > 0 {
			return fmt.Errorf("refusing to project the IaC repo onto the cluster: %s held %d records when this change was committed and has none now — something emptied it in between; the cluster was left as it was, fix the repo first", dnsRepoFile, wantRecords)
		}
		err = s.kube.PatchConfigMapData(ctx, dnsNamespace, dnsHostsCM, cm.ResourceVersion, data, ann)
		if err == nil {
			return nil
		}
		if errors.Is(err, kubeapi.ErrConflict) && attempt < dnsWriteAttempts {
			ui.Warnf(os.Stderr, "the ConfigMap moved; re-reading and retrying (%d/%d)", attempt, dnsWriteAttempts)
			continue
		}
		return fmt.Errorf("the IaC repo holds the change, but the live ConfigMap patch failed (%w) — retry, or sync the coredns app in ArgoCD", err)
	}
}

// dnsActor names who made the change in the commit and the annotation. The
// local login is what the audit needs to start from; the git commit itself
// carries the token's identity as author.
func dnsActor() string {
	if u, err := osuser.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

// dnsVerifyAnswers polls the fleet resolver until the record answers with the
// address that was just registered — the same contract inject holds: OK on
// screen means the thing actually works, not that an API call succeeded.
func dnsVerifyAnswers(ctx context.Context, resolver, hostname, ip string) error {
	ui.Infof(os.Stderr, "verifying against %s (records propagate within about a minute)…", resolver)
	deadline := time.Now().Add(dnsVerifyFor)
	for {
		addrs, err := dnsResolveVia(ctx, resolver, hostname)
		if err == nil && slices.Contains(addrs, ip) {
			ui.Successf(os.Stdout, "%s answers with %s.", hostname, ip)
			return nil
		}
		if time.Now().After(deadline) {
			got := strings.Join(addrs, ", ")
			if got == "" {
				got = "no answer"
			}
			return fmt.Errorf("registered, but %s still answers %q after %s — check the coredns pods (`kubectl -n %s get pods`)",
				hostname, got, strutil.CompactDuration(dnsVerifyFor), dnsNamespace)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(dnsVerifyEvery):
		}
	}
}

// dnsResolveVia asks one specific resolver, not the workstation's own stack —
// the question is what the fleet's DNS answers, and the workstation may be
// pointed anywhere. The dial honours the network Go asks for: a truncated
// UDP answer is retried over TCP, and a dialer that ignored that would retry
// over UDP and truncate again.
func dnsResolveVia(ctx context.Context, resolver, name string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, resolver)
		},
	}
	qctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return r.LookupHost(qctx, name)
}

// zoneBindings reads the Corefile's zone→hosts-file bindings from the live
// cluster — the only authority on which file serves which zone.
func (s *dnsSession) zoneBindings(ctx context.Context) (map[string]string, error) {
	core, err := s.kube.GetConfigMap(ctx, dnsNamespace, dnsCorefileCM)
	if err != nil {
		return nil, fmt.Errorf("read the Corefile from %s/%s: %w", dnsNamespace, dnsCorefileCM, err)
	}
	bindings := dnshosts.ZoneBindings(core.Data["Corefile"])
	if len(bindings) == 0 {
		return nil, fmt.Errorf("the Corefile in %s/%s declares no hosts-file zones", dnsNamespace, dnsCorefileCM)
	}
	return bindings, nil
}

// dnsZoneKey resolves which hosts file a record belongs in: the Corefile's
// bindings, longest-suffix matched — or the operator's --zone, validated
// against the same bindings. The key must already exist in data (the repo's
// zone set); a binding the repo file has no key for is a Corefile↔repo
// mismatch, reported rather than papered over with a new key.
func dnsZoneKey(bindings, data map[string]string, hostname, zoneFlag string) (key, zone string, err error) {
	if zoneFlag != "" {
		k, ok := bindings[zoneFlag]
		if !ok {
			return "", "", fmt.Errorf("no zone %q in the Corefile (have: %s)", zoneFlag, strings.Join(slices.Sorted(maps.Keys(bindings)), ", "))
		}
		zone, key = zoneFlag, k
	} else {
		zone, key = dnshosts.ZoneKeyFor(hostname, bindings)
		if key == "" {
			return "", "", fmt.Errorf("the Corefile has no hosts file for zone %q", zone)
		}
	}
	// Checked against the repo's zones (data), not the live ConfigMap, and for
	// both the inferred and the --zone path — so no branch can reach the edit
	// with a key the repo file does not carry (which would create a new zone
	// key silently, or assign into a nil map).
	if _, ok := data[key]; !ok {
		return "", "", fmt.Errorf("the Corefile serves zone %q from %s, but the IaC repo file has no such key", zone, key)
	}
	return key, zone, nil
}
