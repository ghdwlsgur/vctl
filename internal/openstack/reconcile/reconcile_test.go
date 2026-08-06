package reconcile

import (
	"context"
	"errors"
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
	kind string
	id   string
	at   time.Time
	err  error
}

type fakeRepo struct {
	writes    []write
	result    map[string]store.ReconcileResult
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

func (r *fakeRepo) Reconcile(_ context.Context, in store.ReconcileInput) (store.ReconcileResult, error) {
	r.writes = append(r.writes, write{kind: "reconcile", id: in.DeploymentID, at: in.ObservedAt})
	if err := r.fail("reconcile", in.DeploymentID); err != nil {
		return store.ReconcileResult{}, err
	}
	return r.result[in.DeploymentID], nil
}

func (r *fakeRepo) RecordRun(_ context.Context, id string, _ store.ReconcileResult, at time.Time, runErr error) error {
	r.writes = append(r.writes, write{kind: "run", id: id, at: at, err: runErr})
	return r.fail("run", id)
}

func (r *fakeRepo) RecordControlHosts(_ context.Context, id string, _ []string, at time.Time) error {
	r.writes = append(r.writes, write{kind: "control", id: id, at: at})
	return r.fail("control", id)
}

func (r *fakeRepo) ReplaceInstances(_ context.Context, id string, rows []store.Instance, at time.Time) (int, error) {
	r.writes = append(r.writes, write{kind: "instances", id: id, at: at})
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
	repo := &fakeRepo{result: map[string]store.ReconcileResult{"b": {Confirmed: []string{"h1"}}}}

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
	repo := &fakeRepo{result: map[string]store.ReconcileResult{"a": {Confirmed: []string{"h1"}}}}

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
			repo := &fakeRepo{
				failOn: kind,
				result: map[string]store.ReconcileResult{"a": {Confirmed: []string{"h1"}}},
			}

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
	repo := &fakeRepo{result: map[string]store.ReconcileResult{"a": {Confirmed: []string{"h1"}}}}

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
	repo := &fakeRepo{result: map[string]store.ReconcileResult{"a": {Confirmed: []string{"h1"}}}}

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
