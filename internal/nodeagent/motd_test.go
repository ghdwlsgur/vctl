package nodeagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// farmSink is a fakeStatusSink whose host is in a farm.
type farmSink struct {
	fakeStatusSink
	farms   []store.FarmTopology
	farmErr error
}

func (f *farmSink) FarmTopologies(context.Context, string) ([]store.FarmTopology, error) {
	return f.farms, f.farmErr
}

func oneFarm() []store.FarmTopology {
	return []store.FarmTopology{{
		DisplayName:  "seoul-b",
		State:        "active",
		SyncedAt:     time.Date(2026, 8, 25, 5, 57, 47, 0, time.UTC),
		ControlNames: []string{"sre-srv-0058"},
		Members: []store.FarmMember{
			{Hostname: "sre-srv-0025", IP: "192.168.201.52", NovaHostname: "sre-srv-0025"},
			{Hostname: "sre-srv-0058", IP: "192.168.201.53", NovaHostname: "sre-srv-0058"},
		},
	}}
}

// --once means one of each enabled pass, and the MOTD pass is one of them:
// the smoke test that runs the agent once must leave the banner behind.
func TestOnceRendersTheMOTD(t *testing.T) {
	path := filepath.Join(t.TempDir(), "motd")
	sink := &farmSink{farms: oneFarm()}
	a := &Agent{
		Hostname: "sre-srv-0025",
		Once:     true,
		MOTDPath: path,
		Warnf:    t.Logf, Infof: t.Logf,
		OpenSink: func(context.Context) (Sink, error) { return sink, nil },
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("banner not written: %v", err)
	}
	if !strings.Contains(string(b), "Cluster Topology — seoul-b") ||
		!strings.Contains(string(b), "(sre-srv-0025)  <- HERE") {
		t.Fatalf("banner content wrong:\n%s", b)
	}
}

// A host in no farm must never have its file claimed: whatever is at the path
// — somebody else's banner — stays byte-identical.
func TestNoFarmLeavesTheFileAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "motd")
	const somebodyElses = "hand-written banner\n"
	if err := os.WriteFile(path, []byte(somebodyElses), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := &farmSink{} // no farms
	a := &Agent{
		Hostname: "sre-srv-0023",
		Once:     true,
		MOTDPath: path,
		Warnf:    t.Logf, Infof: t.Logf,
		OpenSink: func(context.Context) (Sink, error) { return sink, nil },
	}
	if err := a.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != somebodyElses {
		t.Fatalf("file was claimed: %q", b)
	}
}

// A topology read failing says nothing about the connection, so the handle the
// heartbeat shares must survive it — same contract as a capability write.
func TestMOTDReadFailureKeepsTheHandle(t *testing.T) {
	sink := &farmSink{farmErr: errors.New("permission denied for table openstack_memberships")}
	c := &conn{open: func(context.Context) (Sink, error) { return sink, nil }}
	a := &Agent{Hostname: "h1", MOTDPath: filepath.Join(t.TempDir(), "motd"), Warnf: t.Logf, Infof: t.Logf}

	a.motdPass(context.Background(), c)

	if sink.closed {
		t.Fatal("a failed topology read must not drop the shared handle")
	}
	if _, err := os.Stat(a.MOTDPath); !os.IsNotExist(err) {
		t.Fatalf("nothing should be written on a failed read: %v", err)
	}
}
