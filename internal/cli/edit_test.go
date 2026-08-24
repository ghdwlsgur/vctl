package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func rowsFull(rows ...store.Server) []store.InventoryRow {
	out := make([]store.InventoryRow, 0, len(rows))
	for _, s := range rows {
		out = append(out, store.InventoryRow{Server: s})
	}
	return out
}

// An empty flag means "leave this alone", not "set it to empty". Losing that
// distinction is how a partial edit silently blanks the fields the operator did
// not mention — and these are precisely the columns sync refuses to rewrite,
// so nothing would restore them.
func TestHostEditsTreatsUnsetFlagsAsNoChange(t *testing.T) {
	if !(hostEdits{}).empty() {
		t.Error("a hostEdits with nothing set is not reported as empty")
	}
	for name, e := range map[string]hostEdits{
		"dc":        {DC: "seoul-onprem"},
		"user":      {User: "rocky"},
		"jump":      {JumpVia: "bastion-01"},
		"name":      {Name: "web-02"},
		"extra-ip":  {ExtraIPs: []string{"10.0.0.1"}},
		"clear-ips": {clearIPs: true},
	} {
		if e.empty() {
			t.Errorf("%s was set but hostEdits reports empty", name)
		}
	}
}

// Clearing needs its own spelling. --jump "" cannot mean "make it direct",
// because that is indistinguishable from not passing the flag.
func TestHostEditsClearingHasAnExplicitSpelling(t *testing.T) {
	if !(hostEdits{JumpVia: ""}).empty() {
		t.Error(`--jump "" was treated as a change`)
	}
	if (hostEdits{JumpVia: jumpDirect}).empty() {
		t.Error(`--jump direct was not treated as a change`)
	}
	if (hostEdits{clearIPs: true}).empty() {
		t.Error("--clear-extra-ips was not treated as a change")
	}
}

func TestHostEditsValidateRejectsUnusableChanges(t *testing.T) {
	st := &fakeLister{rows: rowsFull(
		store.Server{Hostname: "web-01"},
		store.Server{Hostname: "bastion-01"},
	)}
	tests := []struct {
		name string
		e    hostEdits
		want string
	}{
		{"IP 가 아닌 여분 주소", hostEdits{ExtraIPs: []string{"nope"}}, "--extra-ip"},
		{"현재 이름으로 개명", hostEdits{Name: "web-01"}, "current hostname"},
		{"자기 자신을 점프", hostEdits{JumpVia: "web-01"}, "itself"},
		{"개명 후의 이름을 점프", hostEdits{Name: "web-09", JumpVia: "web-09"}, "itself"},
		{"등록되지 않은 점프", hostEdits{JumpVia: "ghost-01"}, "not in the inventory"},
		// servers.hostname is UNIQUE, so this otherwise fails in the database with
		// a message naming an index instead of the host that already has the name.
		{"이미 쓰이는 이름으로 개명", hostEdits{Name: "bastion-01"}, "already in the inventory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.e.validate(context.Background(), st, "web-01")
			if err == nil {
				t.Fatalf("accepted %+v", tc.e)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// "direct" is a value, not a host, so it must not be looked up in the
// inventory — there is no host by that name and the check would reject it.
func TestHostEditsValidateAcceptsClearingTheJumpHost(t *testing.T) {
	st := &fakeLister{rows: rowsFull(store.Server{Hostname: "web-01"})}
	if err := (hostEdits{JumpVia: jumpDirect}).validate(context.Background(), st, "web-01"); err != nil {
		t.Fatalf("rejected --jump direct: %v", err)
	}
}

// A typo must fail before anything is written. Without this, each edit step
// would report "no host named ..." on its own and a multi-field edit would
// print the same error several times.
func TestFindHostNamesTheMissingHost(t *testing.T) {
	st := &fakeLister{rows: rowsFull(store.Server{Hostname: "web-01"})}
	if _, err := findHost(context.Background(), st, "web-99"); err == nil {
		t.Fatal("findHost accepted a hostname that is not in the inventory")
	} else if !strings.Contains(err.Error(), "web-99") {
		t.Errorf("error %q does not name the host", err)
	}
	if got, err := findHost(context.Background(), st, "web-01"); err != nil || got.Hostname != "web-01" {
		t.Errorf("findHost(web-01) = %v, %v", got.Hostname, err)
	}
}

// Deleting a jump host strands everything behind it. Repointing those hosts
// automatically would leave them "direct" and unreachable with nothing saying
// why, so the delete has to stop and name them.
func TestJumpDependentsFindsHostsThatWouldBeStranded(t *testing.T) {
	st := &fakeLister{rows: rowsFull(
		store.Server{Hostname: "bastion-01"},
		store.Server{Hostname: "web-01", JumpVia: "bastion-01"},
		store.Server{Hostname: "web-02", JumpVia: "bastion-01"},
		store.Server{Hostname: "web-03"},
	)}
	got, err := jumpDependents(context.Background(), st, "bastion-01")
	if err != nil {
		t.Fatalf("jumpDependents: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("jumpDependents = %v, want web-01 and web-02", got)
	}

	none, err := jumpDependents(context.Background(), st, "web-03")
	if err != nil {
		t.Fatalf("jumpDependents: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("jumpDependents(web-03) = %v, want none", none)
	}
}
