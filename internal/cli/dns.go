package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	osuser "os/user"
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
	dnsNamespace   = "dns-system"
	dnsHostsCM     = "coredns-hosts"
	dnsCorefileCM  = "coredns-corefile"
	dnsRepoFile    = "configmap-hosts.yaml"
	dnsRepoBranch  = "main"
	dnsStampAnn    = "vctl.sre.local/last-change"
	dnsVerifyEvery = 3 * time.Second
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
	return cmd
}

func argOr(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// dnsSession is everything one dns command needs, opened once: the cluster
// client, and — for writes — the repo client.
type dnsSession struct {
	kube *kubeapi.Client
	git  *gitlabapi.Client
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
	s.git, err = gitlabapi.New(a.Cfg.DNSGitBase, tok["token"], config.SRERootCA)
	if err != nil {
		return nil, err
	}
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
	for _, key := range dnsZoneKeys(cm.Data) {
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

// dnsZoneKeys orders the zone files the way the repo file does, extras after.
func dnsZoneKeys(data map[string]string) []string {
	rendered := dnshosts.RenderConfigMapYAML(data)
	var keys []string
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(line, "  ") && strings.HasSuffix(line, ": |") {
			keys = append(keys, strings.TrimSuffix(strings.TrimSpace(line), ": |"))
		}
	}
	return keys
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
	return dnsMutate(ctx, s, "add "+hostname+" "+ip,
		func(cm *kubeapi.ConfigMap) (string, error) {
			key, zone, err := s.zoneKey(ctx, cm, hostname, zoneFlag)
			if err != nil {
				return "", err
			}
			// Against every zone file, not just the target: the same name
			// answering from two files is a coin flip per query.
			for k, text := range cm.Data {
				if have, ok := dnshosts.Lookup(text, hostname); ok {
					if have == ip {
						ui.Infof(os.Stderr, "%s → %s is already registered in %s.", hostname, ip, k)
						return "", errDNSNoChange
					}
					return "", fmt.Errorf("%s already answers with %s (in %s); remove it first", hostname, have, k)
				}
			}
			next, err := dnshosts.Add(cm.Data[key], ip, hostname)
			if err != nil {
				return "", err
			}
			ui.Infof(os.Stderr, "filing %s → %s under %s (zone %s)", hostname, ip, key, zone)
			cm.Data[key] = next
			return key, nil
		},
		func() error { return dnsVerifyAnswers(ctx, s.cfg.DNSResolver, hostname, ip) },
	)
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
	return dnsMutate(ctx, s, "rm "+hostname,
		func(cm *kubeapi.ConfigMap) (string, error) {
			for key, text := range cm.Data {
				if next, ok := dnshosts.Remove(text, hostname); ok {
					ip, _ := dnshosts.Lookup(text, hostname)
					ui.Infof(os.Stderr, "removing %s (was %s, in %s)", hostname, ip, key)
					cm.Data[key] = next
					return key, nil
				}
			}
			return "", fmt.Errorf("%s is not registered in any zone file (Corefile template wildcards are not records — see the Corefile)", hostname)
		},
		nil,
	)
}

// errDNSNoChange is the quiet exit for an edit that found its work already
// done — an add that is already present exactly as asked.
var errDNSNoChange = errors.New("no change")

// dnsMutate is the one write path: read the live ConfigMap, apply the edit,
// commit the whole file to the IaC repo, then patch the cluster — in that
// order, because the repo is what a sync reasserts. Conflicts on either side
// re-read and reapply; after three the operator sees the contention instead
// of a clobbered write.
func dnsMutate(ctx context.Context, s *dnsSession, action string,
	edit func(*kubeapi.ConfigMap) (string, error), verify func() error) error {
	for attempt := 1; ; attempt++ {
		cm, err := s.kube.GetConfigMap(ctx, dnsNamespace, dnsHostsCM)
		if err != nil {
			return err
		}
		if _, err := edit(cm); err != nil {
			if errors.Is(err, errDNSNoChange) {
				return nil
			}
			return err
		}

		// Repo first. The rendered file is the whole ConfigMap in the repo's
		// canonical format, so a commit also captures any out-of-band edits
		// the live object accumulated — they become history instead of drift.
		file, err := s.git.GetFile(ctx, s.cfg.DNSGitProject, dnsRepoFile, dnsRepoBranch)
		if err != nil {
			return fmt.Errorf("read %s from the IaC repo: %w", dnsRepoFile, err)
		}
		rendered := dnshosts.RenderConfigMapYAML(cm.Data)
		msg := fmt.Sprintf("dns: %s (vctl by %s)", action, dnsActor())
		if rendered == file.Content {
			ui.Infof(os.Stderr, "IaC repo already carries this state; skipping the commit.")
		} else if err := s.git.UpdateFile(ctx, s.cfg.DNSGitProject, dnsRepoFile, dnsRepoBranch,
			rendered, msg, file.LastCommitID); err != nil {
			if errors.Is(err, gitlabapi.ErrConflict) && attempt < 3 {
				ui.Warnf(os.Stderr, "the repo file moved; re-reading and retrying (%d/3)", attempt)
				continue
			}
			return fmt.Errorf("commit to the IaC repo: %w", err)
		}

		ann := map[string]string{
			dnsStampAnn: fmt.Sprintf("%s %s %s", time.Now().UTC().Format(time.RFC3339), dnsActor(), action),
		}
		if err := s.kube.PatchConfigMapData(ctx, dnsNamespace, dnsHostsCM, cm.ResourceVersion, cm.Data, ann); err != nil {
			if errors.Is(err, kubeapi.ErrConflict) && attempt < 3 {
				ui.Warnf(os.Stderr, "the ConfigMap moved; re-reading and retrying (%d/3)", attempt)
				continue
			}
			// The repo is now ahead of the cluster. Said loudly, with the way
			// out: the truth is committed, only the fast path failed.
			return fmt.Errorf("the change is committed to the IaC repo but the live ConfigMap patch failed (%w) — retry, or apply via ArgoCD sync", err)
		}
		break
	}
	ui.Successf(os.Stdout, "recorded in the IaC repo and the live ConfigMap.")
	if verify == nil {
		ui.Infof(os.Stdout, "propagation: kubelet re-syncs the mounted file within about a minute.")
		return nil
	}
	return verify()
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
		if err == nil {
			for _, a := range addrs {
				if a == ip {
					ui.Successf(os.Stdout, "%s answers with %s.", hostname, ip)
					return nil
				}
			}
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
// pointed anywhere.
func dnsResolveVia(ctx context.Context, resolver, name string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", resolver)
		},
	}
	qctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return r.LookupHost(qctx, name)
}

// zoneKey resolves which hosts file a record belongs in: the Corefile's own
// zone→file bindings, longest-suffix matched — or the operator's --zone,
// validated against the same bindings.
func (s *dnsSession) zoneKey(ctx context.Context, cm *kubeapi.ConfigMap, hostname, zoneFlag string) (key, zone string, err error) {
	core, err := s.kube.GetConfigMap(ctx, dnsNamespace, dnsCorefileCM)
	if err != nil {
		return "", "", err
	}
	bindings := dnshosts.ZoneBindings(core.Data["Corefile"])
	if zoneFlag != "" {
		k, ok := bindings[zoneFlag]
		if !ok {
			zones := make([]string, 0, len(bindings))
			for z := range bindings {
				zones = append(zones, z)
			}
			return "", "", fmt.Errorf("no zone %q in the Corefile (have: %s)", zoneFlag, strings.Join(zones, ", "))
		}
		return k, zoneFlag, nil
	}
	zone, key = dnshosts.ZoneKeyFor(hostname, bindings)
	if key == "" {
		return "", "", fmt.Errorf("the Corefile has no hosts file for zone %q", zone)
	}
	if _, ok := cm.Data[key]; !ok {
		return "", "", fmt.Errorf("the Corefile serves zone %q from %s, but the ConfigMap has no such key", zone, key)
	}
	return key, zone, nil
}
