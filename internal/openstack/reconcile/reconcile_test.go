package reconcile

import (
	"context"
	"errors"
	"github.com/ghdwlsgur/vctl/internal/openstack/membership"
	"slices"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/openstackapi"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// These are the decisions that used to need a terminal, a Vault and a live
// OpenStack to exercise. Each one was made for a reason; this is where the
// reasons are held.

type fakeCreds struct {
	err  map[string]error
	seen []string
}

func (f *fakeCreds) ForFarm(_ context.Context, id string) (openstackapi.Credentials, error) {
	f.seen = append(f.seen, id)
	if err := f.err[id]; err != nil {
		return openstackapi.Credentials{}, err
	}
	return openstackapi.Credentials{AuthURL: "https://" + id}, nil
}

type fakeCloud struct {
	hosts     map[string]openstackapi.HostList
	hostErr   map[string]error
	instances map[string]Listing
	instErr   map[string]error
	asked     []string
	listed    []string
}

func (f *fakeCloud) Hosts(_ context.Context, c openstackapi.Credentials, _ bool) (openstackapi.HostList, error) {
	id := c.AuthURL[len("https://"):]
	f.asked = append(f.asked, id)
	if err := f.hostErr[id]; err != nil {
		return openstackapi.HostList{}, err
	}
	return f.hosts[id], nil
}

func (f *fakeCloud) Instances(_ context.Context, c openstackapi.Credentials, _ bool) (Listing, error) {
	id := c.AuthURL[len("https://"):]
	f.listed = append(f.listed, id)
	if err := f.instErr[id]; err != nil {
		return Listing{}, err
	}
	return f.instances[id], nil
}

type write struct {
	kind     string
	id       string
	at       time.Time
	err      error
	complete bool
}

// fakeRepo records what was written. It no longer supplies the outcome: the
// service decides that now — see membership.Decide — so what the tests assert
// is derived from the hosts the fake cloud reports rather than injected here.
type fakeRepo struct {
	writes    []write
	failOn    string // kind that returns an error
	failOnID  string
	instances int
}

func (r *fakeRepo) fail(kind, id string) error {
	if r.failOn == kind && (r.failOnID == "" || r.failOnID == id) {
		return errors.New(kind + " failed")
	}
	return nil
}

func (r *fakeRepo) Apply(_ context.Context, d membership.Decision) error {
	r.writes = append(r.writes, write{kind: "reconcile", id: d.DeploymentID, at: d.At})
	return r.fail("reconcile", d.DeploymentID)
}

func (r *fakeRepo) RecordRun(_ context.Context, id string, _ membership.Outcome, at time.Time, runErr error) error {
	r.writes = append(r.writes, write{kind: "run", id: id, at: at, err: runErr})
	return r.fail("run", id)
}

func (r *fakeRepo) RecordGhostHosts(_ context.Context, id string, _ []string, at time.Time) error {
	r.writes = append(r.writes, write{kind: "control", id: id, at: at})
	return r.fail("control", id)
}

func (r *fakeRepo) ReplaceInstances(_ context.Context, id string, rows []store.Instance, at time.Time, complete bool) (int, error) {
	r.writes = append(r.writes, write{kind: "instances", id: id, at: at, complete: complete})
	if err := r.fail("instances", id); err != nil {
		return 0, err
	}
	return len(rows), nil
}

func (r *fakeRepo) kinds() []string {
	out := make([]string, 0, len(r.writes))
	for _, w := range r.writes {
		out = append(out, w.kind)
	}
	return out
}

func svc(c *fakeCreds, cl *fakeCloud, r *fakeRepo) *Service {
	at := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	return &Service{Creds: c, Cloud: cl, Repo: r, Now: func() time.Time { return at }}
}

func complete(hosts ...string) openstackapi.HostList {
	return openstackapi.HostList{Hosts: hosts, Complete: true}
}

// A deployment nobody has filed credentials for is the normal state of a new
// farm, not a failure of the run — and the farms after it still get reconciled.
func TestAFarmWithNoCredentialsDoesNotStopTheOthers(t *testing.T) {
	creds := &fakeCreds{err: map[string]error{"a": errors.New("no credentials at kv/…")}}
	cloud := &fakeCloud{hosts: map[string]openstackapi.HostList{"b": complete("h1")}}
	repo := &fakeRepo{}

	rep, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}, {ID: "b", LocalHosts: []string{"h1"}}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcomes[0].NoCredentials == nil {
		t.Error("the farm with no credentials was not reported as such")
	}
	if !slices.Contains(cloud.asked, "b") {
		t.Error("the second farm was never asked; one missing credential ended the run")
	}
	if rep.Reached != 1 {
		t.Errorf("reached = %d, want only the farm that answered", rep.Reached)
	}
}

// A control plane that cannot be reached is recorded as such. Without the
// record, a farm failing every six hours is indistinguishable from one nobody
// has configured.
func TestAnUnreachableControlPlaneIsRecorded(t *testing.T) {
	creds := &fakeCreds{}
	cloud := &fakeCloud{hostErr: map[string]error{"a": errors.New("context deadline exceeded")}}
	repo := &fakeRepo{}

	rep, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
	})
	if !errors.Is(err, ErrNothingReached) {
		t.Fatalf("Run error = %v, want ErrNothingReached", err)
	}
	if rep.Outcomes[0].Unreachable == nil {
		t.Error("the failure was not reported on the outcome")
	}
	if got := repo.kinds(); !slices.Equal(got, []string{"run"}) {
		t.Errorf("writes = %v, want only the failure record", got)
	}
	if repo.writes[0].err == nil {
		t.Error("the run was recorded without the reason it failed")
	}
}

// A dry run writes nothing at all — not the membership, not the run record, not
// the VM listing. It also must not record the failure of a farm it could not
// reach, because that is a write too.
func TestADryRunWritesNothing(t *testing.T) {
	creds := &fakeCreds{}
	cloud := &fakeCloud{
		hosts:   map[string]openstackapi.HostList{"a": complete("h1", "ghost")},
		hostErr: map[string]error{"b": errors.New("unreachable")},
	}
	repo := &fakeRepo{}

	rep, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		DryRun: true,
		Farms:  []Farm{{ID: "a", LocalHosts: []string{"h1"}}, {ID: "b", LocalHosts: []string{"h2"}}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(repo.writes) != 0 {
		t.Errorf("a dry run wrote %v", repo.kinds())
	}
	if len(cloud.listed) != 0 {
		t.Errorf("a dry run listed instances for %v", cloud.listed)
	}
	// It still has to say what it would decide, or there is no point running it.
	if !slices.Contains(rep.Outcomes[0].Result.Confirmed, "h1") {
		t.Errorf("preview = %+v, want the host both sides agree on", rep.Outcomes[0].Result)
	}
	if !slices.Contains(rep.Outcomes[0].Result.ControlOnly, "ghost") {
		t.Errorf("preview = %+v, want the host only nova knows", rep.Outcomes[0].Result)
	}
}

// A partial answer changes what the result means — nothing may be demoted on
// one — so it is carried out of the run rather than left for the caller to
// infer from a flag it cannot see.
func TestAPartialAnswerIsNamed(t *testing.T) {
	creds := &fakeCreds{}
	cloud := &fakeCloud{hosts: map[string]openstackapi.HostList{
		"a": {Hosts: []string{"h1"}, Complete: false, ServiceError: "503"},
	}}
	repo := &fakeRepo{}

	rep, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Outcomes[0].Partial == "" {
		t.Fatal("a partial answer was reported as a complete one")
	}
	// Which half is missing matters: no os-services hides controllers, no
	// os-hypervisors hides stopped compute nodes.
	if got := rep.Outcomes[0].Partial; got != "os-services: 503 (controllers are not listed)" {
		t.Errorf("partial reason = %q, want the missing half named", got)
	}
}

// Bookkeeping that fails is a warning, not a failure. The membership was
// settled; losing the note about it is worth saying and not worth undoing.
func TestABookkeepingFailureDoesNotFailTheRun(t *testing.T) {
	for _, kind := range []string{"run", "control", "instances"} {
		t.Run(kind, func(t *testing.T) {
			creds := &fakeCreds{}
			cloud := &fakeCloud{hosts: map[string]openstackapi.HostList{"a": complete("h1")}}
			repo := &fakeRepo{failOn: kind}

			rep, err := svc(creds, cloud, repo).Run(context.Background(), Request{
				Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
			})
			if err != nil {
				t.Fatalf("a failed %s write failed the whole run: %v", kind, err)
			}
			if len(rep.Outcomes[0].Warnings) == 0 {
				t.Errorf("the failed %s write left no warning", kind)
			}
			if !slices.Contains(rep.Outcomes[0].Result.Confirmed, "h1") {
				t.Error("the membership result was lost with the bookkeeping")
			}
		})
	}
}

// A partial answer must not touch the ghost table. RecordGhostHosts deletes the
// ghost rows a pass did not name, so on a partial listing (os-services down,
// controllers missing from ControlOnly through no fault of their own) it would
// delete real ghosts and reset their first_seen_at on the next full pass.
// Membership already holds on a partial answer; the ghost write has to as well.
func TestAPartialAnswerDoesNotTouchTheGhostTable(t *testing.T) {
	creds := &fakeCreds{}
	cloud := &fakeCloud{hosts: map[string]openstackapi.HostList{
		"a": {Hosts: []string{"h1", "ghost"}, Complete: false, ServiceError: "503"},
	}}
	repo := &fakeRepo{}

	rep, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if slices.Contains(repo.kinds(), "control") {
		t.Errorf("a partial answer wrote the ghost table: %v", repo.kinds())
	}
	// The run still happened and was recorded — only the destructive ghost sweep
	// is withheld.
	if !slices.Contains(repo.kinds(), "reconcile") || !slices.Contains(repo.kinds(), "run") {
		t.Errorf("a partial answer skipped the membership write too: %v", repo.kinds())
	}
	if rep.Outcomes[0].Partial == "" {
		t.Error("a partial answer was not named as one")
	}
}

// A complete answer still writes the ghost table — the guard is about partial
// answers, not about turning the feature off.
func TestACompleteAnswerWritesTheGhostTable(t *testing.T) {
	creds := &fakeCreds{}
	cloud := &fakeCloud{hosts: map[string]openstackapi.HostList{"a": complete("h1", "ghost")}}
	repo := &fakeRepo{}

	if _, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Contains(repo.kinds(), "control") {
		t.Errorf("a complete answer did not write the ghost table: %v", repo.kinds())
	}
}

// A dry run must decide exactly what the real run decides — on a partial answer
// too. The preview used to force Complete:true and so could show a demotion the
// real run, holding on the partial answer, would never make.
func TestADryRunOnAPartialAnswerMatchesTheRealRun(t *testing.T) {
	partial := func() *fakeCloud {
		return &fakeCloud{hosts: map[string]openstackapi.HostList{
			"a": {Hosts: []string{"h1"}, Complete: false, ServiceError: "503"},
		}}
	}
	farms := []Farm{{ID: "a", LocalHosts: []string{"h1", "h2"}}}

	dry, err := svc(&fakeCreds{}, partial(), &fakeRepo{}).Run(context.Background(),
		Request{DryRun: true, Farms: farms})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	real, err := svc(&fakeCreds{}, partial(), &fakeRepo{}).Run(context.Background(),
		Request{Farms: farms})
	if err != nil {
		t.Fatalf("real run: %v", err)
	}
	if !slices.Equal(dry.Outcomes[0].Result.LocalOnly, real.Outcomes[0].Result.LocalOnly) {
		t.Errorf("dry LocalOnly %v != real %v — the preview lied about a partial answer",
			dry.Outcomes[0].Result.LocalOnly, real.Outcomes[0].Result.LocalOnly)
	}
}

// The membership write is the exception. A database that will not take it is
// not about this farm, and continuing would keep writing into something that is
// not answering.
func TestAFailedMembershipWriteStopsTheRun(t *testing.T) {
	creds := &fakeCreds{}
	cloud := &fakeCloud{hosts: map[string]openstackapi.HostList{
		"a": complete("h1"), "b": complete("h2"),
	}}
	repo := &fakeRepo{failOn: "reconcile", failOnID: "a"}

	_, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}, {ID: "b", LocalHosts: []string{"h2"}}},
	})
	if err == nil {
		t.Fatal("a failed membership write was reported as success")
	}
	if slices.Contains(cloud.asked, "b") {
		t.Error("the run carried on to the next farm after the database refused a write")
	}
}

// Instances are collected in the same pass, and a failure there never costs the
// membership: a deployment that cannot list servers can still say which hosts
// are its own.
func TestAFailedInstanceListingKeepsTheMembership(t *testing.T) {
	creds := &fakeCreds{}
	cloud := &fakeCloud{
		hosts:   map[string]openstackapi.HostList{"a": complete("h1")},
		instErr: map[string]error{"a": errors.New("nova is down")},
	}
	repo := &fakeRepo{}

	rep, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !slices.Contains(rep.Outcomes[0].Result.Confirmed, "h1") {
		t.Error("a failed VM listing took the membership with it")
	}
	if len(rep.Outcomes[0].Warnings) == 0 {
		t.Error("the listing failure was swallowed")
	}
}

// A run that reached nothing has confirmed nothing. Reporting that as success
// is how a broken credential or a closed route becomes invisible — the listing
// keeps showing whatever the last working run left behind.
func TestARunThatReachedNothingFails(t *testing.T) {
	creds := &fakeCreds{err: map[string]error{"a": errors.New("no credentials")}}
	cloud := &fakeCloud{}
	repo := &fakeRepo{}

	_, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
	})
	if !errors.Is(err, ErrNothingReached) {
		t.Errorf("Run error = %v, want ErrNothingReached", err)
	}
}

// Every write in one farm's pass carries the same instant, so a reader cannot
// see a membership and its run record disagreeing about when they happened.
func TestOnePassRecordsOneInstant(t *testing.T) {
	creds := &fakeCreds{}
	cloud := &fakeCloud{hosts: map[string]openstackapi.HostList{"a": complete("h1")}}
	repo := &fakeRepo{}

	if _, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, w := range repo.writes[1:] {
		if !w.at.Equal(repo.writes[0].at) {
			t.Errorf("%s recorded %v, want the same instant as %s (%v)",
				w.kind, w.at, repo.writes[0].kind, repo.writes[0].at)
		}
	}
}

// Whether the listing was whole has to reach the store, because the store is
// what decides between "these VMs are gone" and "we did not get that far".
//
// A truncated pass still stores what it reached — those rows are current — so
// the write happening is not the question. The question is what it claims.
func TestAPartialInstanceListingIsWrittenAsIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name     string
		complete bool
	}{
		{"whole listing", true},
		{"stopped early", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creds := &fakeCreds{}
			cloud := &fakeCloud{
				hosts: map[string]openstackapi.HostList{"a": complete("h1")},
				instances: map[string]Listing{"a": {
					Instances: []openstackapi.Instance{{ID: "vm-1"}},
					Complete:  tc.complete,
				}},
			}
			repo := &fakeRepo{}

			if _, err := svc(creds, cloud, repo).Run(context.Background(), Request{
				Farms: []Farm{{ID: "a", LocalHosts: []string{"h1"}}},
			}); err != nil {
				t.Fatalf("Run: %v", err)
			}
			var found bool
			for _, w := range repo.writes {
				if w.kind != "instances" {
					continue
				}
				found = true
				if w.complete != tc.complete {
					t.Errorf("stored complete=%v, want %v — the store would %s",
						w.complete, tc.complete,
						map[bool]string{true: "retire VMs it never reached", false: "keep VMs the deployment dropped"}[w.complete])
				}
			}
			if !found {
				t.Error("nothing was written; a truncated pass still stores what it reached")
			}
		})
	}
}

// A run where one farm answered and seven did not is a success by the old
// measure — Run only fails when nothing was reached at all. A timer cannot tell
// that from a healthy run, which is how a broken credential or a closed route
// stays invisible for as long as one farm keeps working.
//
// What counts as failure is the caller's to say, so this reports and does not
// decide.
func TestAReportCountsWhatWentWrongWithoutDeciding(t *testing.T) {
	creds := &fakeCreds{err: map[string]error{"c": errors.New("no credentials")}}
	cloud := &fakeCloud{
		hosts: map[string]openstackapi.HostList{
			"a": complete("h1"),
			"b": {Hosts: []string{"h2"}, Complete: false, ServiceError: "503"},
		},
		hostErr: map[string]error{"d": errors.New("context deadline exceeded")},
	}
	repo := &fakeRepo{}

	rep, err := svc(creds, cloud, repo).Run(context.Background(), Request{
		Farms: []Farm{
			{ID: "a", LocalHosts: []string{"h1"}},
			{ID: "b", LocalHosts: []string{"h2"}},
			{ID: "c", LocalHosts: []string{"h3"}},
			{ID: "d", LocalHosts: []string{"h4"}},
		},
	})
	// Two farms answered, so the run itself is not a failure.
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, tc := range []struct {
		what string
		got  int
		want int
	}{
		{"reached", rep.Reached, 2},
		{"unreachable", rep.Unreachable(), 1},
		{"no credentials", rep.NoCredentials(), 1},
		{"partial", rep.Partial(), 1},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.what, tc.got, tc.want)
		}
	}

	// And the caller picks which of those is worth exiting for.
	if hit := rep.FailOn([]Problem{ProblemUnreachable}); len(hit) != 1 {
		t.Errorf("FailOn(unreachable) = %v, want it to fire", hit)
	}
	if hit := rep.FailOn([]Problem{ProblemWarning}); len(hit) != 0 {
		t.Errorf("FailOn(warning) = %v, want nothing — no farm warned", hit)
	}
	// Asking for nothing is the default and must stay silent, or a timer that
	// upgrades starts reporting a new deployment's missing credentials as an
	// incident.
	if hit := rep.FailOn(nil); len(hit) != 0 {
		t.Errorf("FailOn(nil) = %v, want nothing", hit)
	}
}
