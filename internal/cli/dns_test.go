package cli

import (
	"context"
	"maps"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/dnshosts"
	"github.com/ghdwlsgur/vctl/internal/gitlabapi"
	"github.com/ghdwlsgur/vctl/internal/kubeapi"
)

// The write path is two optimistic writes against two stores, in an order
// that matters. These tests run it against in-memory fakes of both, which is
// the only way to stage the races it exists to survive: a concurrent commit
// between the read and the write, another between the commit and the
// projection, a ConfigMap that moved under the patch.

const testCorefile = `example.com:53 {
    hosts /etc/coredns/hosts/innogrid.hosts {
        fallthrough
    }
}
corp.internal:53 {
    hosts /etc/coredns/hosts/sre.hosts {
        fallthrough
    }
}
.:53 {
    hosts /etc/coredns/hosts/misc.hosts {
        fallthrough
    }
}
`

// fakeDNSRepo is the IaC repo: one file at one commit, with GitLab's
// last_commit_id precondition. Hooks let a test act as a concurrent writer at
// a chosen moment.
type fakeDNSRepo struct {
	content  string
	commit   int
	commits  int // successful UpdateFile calls
	reads    int
	updates  int
	onRead   func(r *fakeDNSRepo, n int) // before the n-th GetFile answers
	onUpdate func(r *fakeDNSRepo, n int) // before the n-th UpdateFile checks its precondition
}

func (r *fakeDNSRepo) id() string { return "c" + strconv.Itoa(r.commit) }

func (r *fakeDNSRepo) GetFile(context.Context, string, string, string) (*gitlabapi.File, error) {
	r.reads++
	if r.onRead != nil {
		r.onRead(r, r.reads)
	}
	return &gitlabapi.File{Content: r.content, LastCommitID: r.id()}, nil
}

func (r *fakeDNSRepo) UpdateFile(_ context.Context, _, _, _, content, _, lastCommitID string) error {
	r.updates++
	if r.onUpdate != nil {
		r.onUpdate(r, r.updates)
	}
	if lastCommitID != r.id() {
		return gitlabapi.ErrConflict
	}
	r.content = content
	r.commit++
	r.commits++
	return nil
}

// concurrentCommit is another writer landing: the content moves and so does
// the commit id, which is what makes a stale precondition fail.
func (r *fakeDNSRepo) concurrentCommit(mutate func(map[string]string)) {
	data, err := dnshosts.ParseConfigMapYAML(r.content)
	if err != nil {
		panic(err)
	}
	mutate(data)
	r.content = dnshosts.RenderConfigMapYAML(data)
	r.commit++
}

// fakeDNSCluster serves the two ConfigMaps the command reads, with the API
// server's resourceVersion precondition and merge-patch semantics.
type fakeDNSCluster struct {
	corefile string
	data     map[string]string
	rv       int
	patches  int
	lastAnn  map[string]string
	bumpOnce bool // the next patch finds the object moved: one spurious conflict
}

func (c *fakeDNSCluster) GetConfigMap(_ context.Context, _, name string) (*kubeapi.ConfigMap, error) {
	if name == dnsCorefileCM {
		return &kubeapi.ConfigMap{Data: map[string]string{"Corefile": c.corefile}}, nil
	}
	return &kubeapi.ConfigMap{ResourceVersion: strconv.Itoa(c.rv), Data: maps.Clone(c.data)}, nil
}

func (c *fakeDNSCluster) PatchConfigMapData(_ context.Context, _, _, rv string, data, ann map[string]string) error {
	if c.bumpOnce {
		c.bumpOnce = false
		c.rv++
		return kubeapi.ErrConflict
	}
	if rv != strconv.Itoa(c.rv) {
		return kubeapi.ErrConflict
	}
	if c.data == nil {
		c.data = map[string]string{}
	}
	maps.Copy(c.data, data)
	c.lastAnn = ann
	c.rv++
	c.patches++
	return nil
}

func zones(sre, innogrid, misc string) map[string]string {
	return map[string]string{"sre.hosts": sre, "innogrid.hosts": innogrid, "misc.hosts": misc}
}

func newDNSFixture(repo, live map[string]string) (*dnsSession, *fakeDNSRepo, *fakeDNSCluster) {
	r := &fakeDNSRepo{content: dnshosts.RenderConfigMapYAML(repo), commit: 1}
	c := &fakeDNSCluster{corefile: testCorefile, data: maps.Clone(live), rv: 10}
	return &dnsSession{kube: c, git: r, cfg: &config.Config{DNSGitProject: "sre/coredns"}}, r, c
}

func repoData(t *testing.T, r *fakeDNSRepo) map[string]string {
	t.Helper()
	data, err := dnshosts.ParseConfigMapYAML(r.content)
	if err != nil {
		t.Fatalf("the repo file no longer parses: %v", err)
	}
	return data
}

func mustAnswer(t *testing.T, where, text, name, ip string) {
	t.Helper()
	got, ok := dnshosts.Lookup(text, name)
	if !ok || got != ip {
		t.Errorf("%s: %s → %q (found=%v), want %s\n%s", where, name, got, ok, ip, text)
	}
}

func TestDNSAddLandsInTheRepoThenTheCluster(t *testing.T) {
	s, repo, cl := newDNSFixture(zones("", "", ""), zones("", "", ""))
	if err := dnsAdd(t.Context(), s, "vault.corp.internal", "192.0.2.10", ""); err != nil {
		t.Fatal(err)
	}
	if repo.commits != 1 {
		t.Errorf("commits = %d, want 1", repo.commits)
	}
	// Filed under the zone the Corefile binds, in both places, identically.
	mustAnswer(t, "repo", repoData(t, repo)["sre.hosts"], "vault.corp.internal", "192.0.2.10")
	mustAnswer(t, "cluster", cl.data["sre.hosts"], "vault.corp.internal", "192.0.2.10")
	if repoData(t, repo)["sre.hosts"] != cl.data["sre.hosts"] {
		t.Error("repo and cluster disagree after a write")
	}
	if !strings.Contains(cl.lastAnn[dnsStampAnn], "add vault.corp.internal 192.0.2.10") {
		t.Errorf("the change stamp does not name the action: %q", cl.lastAnn[dnsStampAnn])
	}
}

// The repo already has the record but the cluster does not — a commit that
// was never synced, a ConfigMap someone reverted. "Already registered" must
// still make the resolver answer, which means projecting the repo anyway.
func TestDNSAddAlreadyInTheRepoStillReassertsTheCluster(t *testing.T) {
	line := "192.0.2.10           vault.corp.internal\n"
	s, repo, cl := newDNSFixture(zones(line, "", ""), zones("", "", ""))
	if err := dnsAdd(t.Context(), s, "vault.corp.internal", "192.0.2.10", ""); err != nil {
		t.Fatal(err)
	}
	if repo.commits != 0 {
		t.Errorf("re-committed an unchanged record (%d commits)", repo.commits)
	}
	if cl.patches != 1 {
		t.Fatalf("cluster patched %d times, want 1 — the repo being right does not make the cluster right", cl.patches)
	}
	mustAnswer(t, "cluster", cl.data["sre.hosts"], "vault.corp.internal", "192.0.2.10")
}

func TestDNSAddRefusesAConflictingAddressWithoutWriting(t *testing.T) {
	line := "192.0.2.10           vault.corp.internal\n"
	s, repo, cl := newDNSFixture(zones(line, "", ""), zones(line, "", ""))
	err := dnsAdd(t.Context(), s, "vault.corp.internal", "192.0.2.99", "")
	if err == nil || !strings.Contains(err.Error(), "already answers with 192.0.2.10") {
		t.Fatalf("err = %v, want the conflict", err)
	}
	if repo.commits != 0 || cl.patches != 0 {
		t.Error("a refused add wrote something")
	}
}

// Another writer commits between our commit and our projection. Projecting
// the snapshot we committed would push a ConfigMap without their record —
// with a fresh resourceVersion, so nothing would refuse it. Projecting the
// repo's HEAD carries both.
func TestDNSProjectionCarriesAConcurrentCommitOntoTheCluster(t *testing.T) {
	s, repo, cl := newDNSFixture(zones("", "", ""), zones("", "", ""))
	repo.onRead = func(r *fakeDNSRepo, n int) {
		if n == 2 { // the projection's read, after our commit
			r.concurrentCommit(func(d map[string]string) {
				d["sre.hosts"], _ = dnshosts.Add(d["sre.hosts"], "192.0.2.20", "other.corp.internal")
			})
		}
	}
	if err := dnsAdd(t.Context(), s, "vault.corp.internal", "192.0.2.10", ""); err != nil {
		t.Fatal(err)
	}
	mustAnswer(t, "cluster", cl.data["sre.hosts"], "vault.corp.internal", "192.0.2.10")
	mustAnswer(t, "cluster", cl.data["sre.hosts"], "other.corp.internal", "192.0.2.20")
}

// Between our commit and our projection the repo file loses every record — a
// bad hand edit, a broken sync. The cluster must keep answering; emptying it
// to match would turn one broken file into a fleet-wide outage.
func TestDNSRefusesToProjectAnEmptiedRepoOntoALiveCluster(t *testing.T) {
	line := "192.0.2.10           vault.corp.internal\n"
	s, repo, cl := newDNSFixture(zones(line, "", ""), zones(line, "", ""))
	repo.onRead = func(r *fakeDNSRepo, n int) {
		if n == 2 {
			r.concurrentCommit(func(d map[string]string) {
				for k := range d {
					d[k] = ""
				}
			})
		}
	}
	err := dnsAdd(t.Context(), s, "new.corp.internal", "192.0.2.11", "")
	if err == nil || !strings.Contains(err.Error(), "has none now") {
		t.Fatalf("err = %v, want the empty-repo refusal", err)
	}
	if cl.patches != 0 {
		t.Error("the cluster was patched from an empty repo file")
	}
	mustAnswer(t, "cluster (untouched)", cl.data["sre.hosts"], "vault.corp.internal", "192.0.2.10")
}

// Our write races another writer's commit. GitLab refuses the stale
// precondition; the retry must re-read and re-apply onto their content, not
// overwrite it with ours.
func TestDNSGitConflictRetriesOnTheWinnersContent(t *testing.T) {
	s, repo, cl := newDNSFixture(zones("", "", ""), zones("", "", ""))
	repo.onUpdate = func(r *fakeDNSRepo, n int) {
		if n == 1 { // they land after our read, before our write
			r.concurrentCommit(func(d map[string]string) {
				d["sre.hosts"], _ = dnshosts.Add(d["sre.hosts"], "192.0.2.20", "other.corp.internal")
			})
		}
	}
	if err := dnsAdd(t.Context(), s, "vault.corp.internal", "192.0.2.10", ""); err != nil {
		t.Fatal(err)
	}
	if repo.commits != 1 || repo.updates != 2 {
		t.Errorf("commits = %d, update attempts = %d; want one refusal then one landing", repo.commits, repo.updates)
	}
	final := repoData(t, repo)["sre.hosts"]
	mustAnswer(t, "repo", final, "vault.corp.internal", "192.0.2.10")
	mustAnswer(t, "repo", final, "other.corp.internal", "192.0.2.20")
	if cl.data["sre.hosts"] != final {
		t.Error("the cluster does not match the repo after the retry")
	}
}

func TestDNSClusterConflictRetriesWithAFreshVersion(t *testing.T) {
	s, _, cl := newDNSFixture(zones("", "", ""), zones("", "", ""))
	cl.bumpOnce = true
	if err := dnsAdd(t.Context(), s, "vault.corp.internal", "192.0.2.10", ""); err != nil {
		t.Fatal(err)
	}
	if cl.patches != 1 {
		t.Errorf("patches = %d, want the retry to land exactly once", cl.patches)
	}
	mustAnswer(t, "cluster", cl.data["sre.hosts"], "vault.corp.internal", "192.0.2.10")
}

// Add keeps a name to one file; a hand edit need not have. Deregistering has
// to mean the name no longer answers, so every file that carries it is edited.
// These are also the last records in the fleet: removing them takes the repo
// to zero, and that is a deregistration this process made, not the emptied-
// repo race the projection guards against — it must go through.
func TestDNSRmRemovesFromEveryZoneFileThatCarriesTheName(t *testing.T) {
	line := "192.0.2.10           dup.example.com\n"
	s, repo, cl := newDNSFixture(zones(line, line, ""), zones(line, line, ""))
	if err := dnsRm(t.Context(), s, "dup.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"sre.hosts", "innogrid.hosts"} {
		if _, ok := dnshosts.Lookup(cl.data[k], "dup.example.com"); ok {
			t.Errorf("dup.example.com still answers from %s after rm", k)
		}
	}
	if repo.commits != 1 {
		t.Errorf("commits = %d, want one commit covering both files", repo.commits)
	}
}

func TestDNSRmOfAnUnknownNameWritesNothing(t *testing.T) {
	s, repo, cl := newDNSFixture(zones("", "", ""), zones("", "", ""))
	err := dnsRm(t.Context(), s, "ghost.example.com")
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("err = %v", err)
	}
	if repo.commits != 0 || cl.patches != 0 {
		t.Error("a refused rm wrote something")
	}
}

func TestDNSAddWithZoneFlagFilesWhereTold(t *testing.T) {
	s, _, cl := newDNSFixture(zones("", "", ""), zones("", "", ""))
	if err := dnsAdd(t.Context(), s, "odd.example.com", "192.0.2.5", "corp.internal"); err != nil {
		t.Fatal(err)
	}
	mustAnswer(t, "cluster", cl.data["sre.hosts"], "odd.example.com", "192.0.2.5")
	if _, ok := dnshosts.Lookup(cl.data["innogrid.hosts"], "odd.example.com"); ok {
		t.Error("--zone was not honoured; the record went where the name implied")
	}
}

func TestDNSZoneKeyValidatesBothPaths(t *testing.T) {
	b := dnshosts.ZoneBindings(testCorefile)
	data := zones("", "", "")
	if key, zone, err := dnsZoneKey(b, data, "x.example.com", ""); err != nil || key != "innogrid.hosts" || zone != "example.com" {
		t.Errorf("inferred (%q, %q, %v)", key, zone, err)
	}
	if _, _, err := dnsZoneKey(b, data, "x.example.com", "nope.zone"); err == nil || !strings.Contains(err.Error(), "no zone") {
		t.Errorf("an unknown --zone was accepted: %v", err)
	}
	// A zone the Corefile serves from a file the repo does not carry is a
	// mismatch to report, not a key to invent.
	delete(data, "misc.hosts")
	if _, _, err := dnsZoneKey(b, data, "x.other.org", ""); err == nil || !strings.Contains(err.Error(), "no such key") {
		t.Errorf("a missing repo key was papered over: %v", err)
	}
	if _, ok := data["misc.hosts"]; ok {
		t.Error("zone resolution created a key")
	}
}

// The resolver is a VIP over several pods that catch up at different moments.
// One answer is one pod; the verdict needs a streak, and a miss in the middle
// of one starts it over.
func TestDNSVerifyNeedsAStreakOfAnswers(t *testing.T) {
	oldEvery, oldFor, oldResolve := dnsVerifyEvery, dnsVerifyFor, dnsResolve
	t.Cleanup(func() { dnsVerifyEvery, dnsVerifyFor, dnsResolve = oldEvery, oldFor, oldResolve })
	dnsVerifyEvery, dnsVerifyFor = time.Millisecond, time.Second

	// pod A has it, pod B has not, then everyone has it.
	script := []bool{true, false, true, true, false, true, true, true}
	calls := 0
	dnsResolve = func(context.Context, string, string) ([]string, error) {
		i := min(calls, len(script)-1)
		calls++
		if script[i] {
			return []string{"192.0.2.10"}, nil
		}
		return nil, nil
	}
	if err := dnsVerifyAnswers(t.Context(), "198.51.100.53:53", "x.example.com", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if calls != len(script) {
		t.Errorf("verified after %d polls, want %d — a streak of %d broken by misses", calls, len(script), dnsVerifyStreak)
	}
}

func TestDNSVerifyGivesUpAfterTheWindow(t *testing.T) {
	oldEvery, oldFor, oldResolve := dnsVerifyEvery, dnsVerifyFor, dnsResolve
	t.Cleanup(func() { dnsVerifyEvery, dnsVerifyFor, dnsResolve = oldEvery, oldFor, oldResolve })
	dnsVerifyEvery, dnsVerifyFor = time.Millisecond, 20*time.Millisecond
	dnsResolve = func(context.Context, string, string) ([]string, error) { return []string{"192.0.2.99"}, nil }
	err := dnsVerifyAnswers(t.Context(), "198.51.100.53:53", "x.example.com", "192.0.2.10")
	if err == nil || !strings.Contains(err.Error(), "still answers") {
		t.Fatalf("err = %v, want the timeout verdict naming what it did answer", err)
	}
}
