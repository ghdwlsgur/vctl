package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// validateServer runs before the insert, so what it rejects never reaches the
// database. The point is not schema validity — Postgres would take most of
// these — but whether `vctl ssh` could use the row afterwards. A row that
// stores fine and fails at connect time is worse than a rejected add, because
// the failure surfaces when nobody is thinking about the add any more.
func TestValidateServerRejectsRowsSSHCouldNotUse(t *testing.T) {
	base := store.Server{Hostname: "web-01", IP: "192.0.2.10", User: "ubuntu", DC: "seoul-onprem", Port: 22}

	tests := []struct {
		name string
		mut  func(*store.Server)
		want string
	}{
		{"빈 hostname", func(s *store.Server) { s.Hostname = " " }, "--host"},
		{"공백뿐인 user", func(s *store.Server) { s.User = "   " }, "--user"},
		{"빈 dc", func(s *store.Server) { s.DC = "" }, "--dc"},
		{"IP 가 아닌 값", func(s *store.Server) { s.IP = "web-01.example" }, "--ip"},
		{"범위 밖 포트", func(s *store.Server) { s.Port = 70000 }, "--port"},
		{"포트 0", func(s *store.Server) { s.Port = 0 }, "--port"},
		// A host that jumps through itself produces a chain with no exit; the
		// connect path would loop rather than fail cleanly.
		{"자기 자신을 점프", func(s *store.Server) { s.JumpVia = s.Hostname }, "itself"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sv := base
			tc.mut(&sv)
			err := validateServer(context.Background(), nil, sv)
			if err == nil {
				t.Fatalf("accepted %+v", sv)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q, so the operator cannot tell which field to fix", err, tc.want)
			}
		})
	}
}

// The happy path must not require a jump host: most hosts are reached directly,
// and demanding one would make the common case the awkward one.
func TestValidateServerAcceptsADirectHost(t *testing.T) {
	sv := store.Server{Hostname: "web-01", IP: "192.0.2.10", User: "ubuntu", DC: "seoul-onprem", Port: 22}
	if err := validateServer(context.Background(), nil, sv); err != nil {
		t.Fatalf("rejected a valid direct host: %v", err)
	}
}

// nonEmpty is what the form uses to stop blank answers. Whitespace has to count
// as blank — a hostname of " " is accepted by every string check that only
// tests for "" and produces an inventory entry nobody can type.
func TestNonEmptyTreatsWhitespaceAsBlank(t *testing.T) {
	check := nonEmpty("hostname")
	for _, s := range []string{"", " ", "\t", "\n  "} {
		if err := check(s); err == nil {
			t.Errorf("nonEmpty accepted %q", s)
		}
	}
	if err := check(" web-01 "); err != nil {
		t.Errorf("nonEmpty rejected a padded but real value: %v", err)
	}
}

// With every required flag set there is nothing to ask, so completeServer must
// not reach for a terminal. This is the path CI takes.
func TestCompleteServerDoesNotPromptWhenFlagsAreComplete(t *testing.T) {
	sv := store.Server{Hostname: "web-01", IP: "192.0.2.10", User: "ubuntu", DC: "seoul-onprem", Port: 22}
	if err := completeServer(context.Background(), nil, &sv); err != nil {
		t.Fatalf("completeServer: %v", err)
	}
	if sv.Hostname != "web-01" {
		t.Errorf("completeServer changed a supplied value: %q", sv.Hostname)
	}
}

// fakeLister stands in for the inventory so the branches that consult it can be
// tested without a database. Those branches are the interesting ones: whether a
// jump host exists decides if the row is usable at all.
type fakeLister struct {
	rows []store.InventoryRow
	err  error
	dc   string // records the filter passed in
}

func (f *fakeLister) ListInventory(_ context.Context, dc string) ([]store.InventoryRow, error) {
	f.dc = dc
	return f.rows, f.err
}

func rowsWith(hosts ...string) []store.InventoryRow {
	out := make([]store.InventoryRow, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, store.InventoryRow{Server: store.Server{Hostname: h}})
	}
	return out
}

// A jump host that is not in the inventory yields a row that stores cleanly and
// fails at connect time. Catching it at add time is the whole point of asking
// the inventory here.
func TestValidateServerRejectsAJumpHostThatIsNotRegistered(t *testing.T) {
	st := &fakeLister{rows: rowsWith("bastion-01", "web-02")}
	sv := store.Server{
		Hostname: "web-01", IP: "192.0.2.10", User: "ubuntu",
		DC: "seoul-onprem", Port: 22, JumpVia: "bastion-99",
	}
	err := validateServer(context.Background(), st, sv)
	if err == nil {
		t.Fatal("accepted a jump host that is not in the inventory")
	}
	if !strings.Contains(err.Error(), "bastion-99") {
		t.Errorf("error %q does not name the missing host", err)
	}
}

func TestValidateServerAcceptsARegisteredJumpHost(t *testing.T) {
	st := &fakeLister{rows: rowsWith("bastion-01", "web-02")}
	sv := store.Server{
		Hostname: "web-01", IP: "192.0.2.10", User: "ubuntu",
		DC: "seoul-onprem", Port: 22, JumpVia: "bastion-01",
	}
	if err := validateServer(context.Background(), st, sv); err != nil {
		t.Fatalf("rejected a registered jump host: %v", err)
	}
}

// The lookup is a courtesy, not a gate. Failing the add because the check that
// would have helped is unavailable trades a real problem for a possible one —
// and the database being unreachable is exactly when an operator is trying to
// repair the inventory.
func TestValidateServerStillAddsWhenTheInventoryLookupFails(t *testing.T) {
	st := &fakeLister{err: errLookup{}}
	sv := store.Server{
		Hostname: "web-01", IP: "192.0.2.10", User: "ubuntu",
		DC: "seoul-onprem", Port: 22, JumpVia: "bastion-01",
	}
	if err := validateServer(context.Background(), st, sv); err != nil {
		t.Fatalf("a failed lookup blocked the add: %v", err)
	}
}

type errLookup struct{}

func (errLookup) Error() string { return "inventory unavailable" }

// The datacenter suggestions exist to stop the same site being spelled three
// ways. Duplicates and blanks in the inventory must not become duplicate and
// blank options.
func TestKnownDCsDedupesAndDropsBlanks(t *testing.T) {
	st := &fakeLister{rows: []store.InventoryRow{
		{Server: store.Server{DC: "seoul-onprem"}},
		{Server: store.Server{DC: "incheon-vm"}},
		{Server: store.Server{DC: "seoul-onprem"}},
		{Server: store.Server{DC: ""}},
		{Server: store.Server{DC: "incheon-vm"}},
	}}
	got := knownDCs(context.Background(), st)
	want := []string{"seoul-onprem", "incheon-vm"}
	if len(got) != len(want) {
		t.Fatalf("knownDCs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("knownDCs = %v, want %v (order follows first appearance)", got, want)
		}
	}
	if st.dc != "" {
		t.Errorf("knownDCs filtered by dc=%q; it must see every label", st.dc)
	}
}

// A fresh inventory has nothing to suggest. Returning an empty list rather than
// erroring is what lets the form fall back to free text.
func TestKnownDCsReturnsNothingOnAFailedLookup(t *testing.T) {
	if got := knownDCs(context.Background(), &fakeLister{err: errLookup{}}); len(got) != 0 {
		t.Errorf("knownDCs = %v, want empty", got)
	}
}

// dcField picks the widget from what the inventory knows: a chooser once there
// are labels, free text while there are none. Getting this backwards would
// either offer an empty menu or make every add retype the label.
func TestDCFieldChoosesWidgetFromKnownLabels(t *testing.T) {
	var target string
	if got := dcField(nil, &target); got == nil {
		t.Fatal("dcField returned nil for an empty inventory")
	}
	empty := dcField(nil, &target)
	filled := dcField([]string{"seoul-onprem"}, &target)
	if fmt.Sprintf("%T", empty) == fmt.Sprintf("%T", filled) {
		t.Errorf("dcField returned %T in both cases; the widget must differ", empty)
	}
}

// Extra addresses are what `vctl ssh --server <ip>` matches on and what the
// WireGuard view resolves endpoints through, so a typo here produces a host
// that looks registered and cannot be found by address.
func TestValidateServerChecksExtraAddresses(t *testing.T) {
	base := store.Server{Hostname: "web-01", IP: "192.0.2.10", User: "ubuntu", DC: "seoul-onprem", Port: 22}

	bad := base
	bad.ExtraIPs = []string{"192.0.2.11", "not-an-ip"}
	err := validateServer(context.Background(), nil, bad)
	if err == nil {
		t.Fatal("accepted an unparseable extra address")
	}
	if !strings.Contains(err.Error(), "not-an-ip") {
		t.Errorf("error %q does not name the bad value", err)
	}

	// Repeating the primary is not an error Postgres would raise — extra_ips is
	// just an array — but it makes the listing claim a second address the host
	// does not separately answer on.
	dup := base
	dup.ExtraIPs = []string{base.IP}
	if err := validateServer(context.Background(), nil, dup); err == nil {
		t.Error("accepted an extra address identical to --ip")
	}

	ok := base
	ok.ExtraIPs = []string{"192.0.2.11", " 192.0.2.12 "}
	if err := validateServer(context.Background(), nil, ok); err != nil {
		t.Errorf("rejected valid extra addresses: %v", err)
	}
}

// The form takes one line because it cannot repeat a field the way a flag
// repeats. A pasted list usually carries stray whitespace and a trailing comma,
// and turning those into empty addresses would store rows nothing matches.
func TestSplitIPListDropsBlanksAndTrims(t *testing.T) {
	got := splitIPList(" 10.0.0.1 ,10.0.0.2,, 10.0.0.3 ,")
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if len(got) != len(want) {
		t.Fatalf("splitIPList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitIPList = %v, want %v", got, want)
		}
	}
	if got := splitIPList("  , ,"); len(got) != 0 {
		t.Errorf("splitIPList(blank) = %v, want empty", got)
	}
}
