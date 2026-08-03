package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/ghdwlsgur/vctl/internal/store"
)

// An explicit hostname wins over the picker. Otherwise `vctl edit web-01` in a
// script would stop and wait for a keypress.
func TestResolveHostPrefersTheArgument(t *testing.T) {
	st := &fakeLister{rows: rowsFull(
		store.Server{Hostname: "web-01", IP: "192.0.2.10"},
		store.Server{Hostname: "web-02", IP: "192.0.2.11"},
	)}
	got, err := resolveHost(context.Background(), st, []string{"web-02"}, "pick")
	if err != nil {
		t.Fatalf("resolveHost: %v", err)
	}
	if got.Hostname != "web-02" {
		t.Errorf("resolveHost = %q, want web-02", got.Hostname)
	}
	if _, err := resolveHost(context.Background(), st, []string{"web-99"}, "pick"); err == nil {
		t.Error("resolveHost accepted a hostname that is not in the inventory")
	}
}

// No terminal and no hostname is an error, not a guess. A delete that picked a
// host on its own because it could not ask is the failure this exists to
// prevent; the test runs without a TTY, which is the condition itself.
func TestResolveHostRefusesToGuessWithoutATerminal(t *testing.T) {
	st := &fakeLister{rows: rowsFull(store.Server{Hostname: "web-01"})}
	_, err := resolveHost(context.Background(), st, nil, "pick")
	if err == nil {
		t.Fatal("resolveHost picked a host with no argument and no terminal")
	}
	if !strings.Contains(err.Error(), "hostname is required") {
		t.Errorf("error %q does not say a hostname is required", err)
	}
}

// An empty inventory has nothing to pick, and "nothing to choose from" does not
// tell an operator that the fix is `vctl add`.
func TestPickHostRefusesAnEmptyInventory(t *testing.T) {
	_, err := pickHost(nil, "pick")
	if err == nil {
		t.Fatal("pickHost ran on an empty inventory")
	}
	if !strings.Contains(err.Error(), "vctl add") {
		t.Errorf("error %q does not point at vctl add", err)
	}
}

// The picker rows have to line up. Widths are computed across every row, so the
// IP column starts at the same offset on all of them regardless of how long the
// longest hostname is.
func TestHostPickLabelsAlignColumns(t *testing.T) {
	rows := rowsFull(
		store.Server{Hostname: "db-1", IP: "192.0.2.10", DC: "seoul-onprem"},
		store.Server{Hostname: "web-server-01", IP: "192.0.2.11", DC: "incheon", JumpVia: "bastion-01"},
	)
	labels := hostPickLabels(rows)
	if len(labels) != 2 {
		t.Fatalf("hostPickLabels returned %d labels for 2 rows", len(labels))
	}
	first := strings.Index(labels[0], "192.0.2.10")
	second := strings.Index(labels[1], "192.0.2.11")
	if first < 0 || second < 0 {
		t.Fatalf("labels do not carry the addresses: %q", labels)
	}
	// Padding is by display column, so the comparison has to be too — a byte
	// offset would drift the moment a hostname is truncated with an ellipsis.
	if a, b := lipgloss.Width(labels[0][:first]), lipgloss.Width(labels[1][:second]); a != b {
		t.Errorf("address column starts at %d and %d; the rows do not line up", a, b)
	}
	if !strings.Contains(labels[1], "via bastion-01") {
		t.Errorf("label %q does not name the jump host", labels[1])
	}
	// A host with no jump must not carry the padding for one, or every row in a
	// mostly-direct inventory ends in a run of spaces.
	if labels[0] != strings.TrimRight(labels[0], " ") {
		t.Errorf("label %q has trailing whitespace", labels[0])
	}
	if !strings.Contains(labels[0], "seoul-onprem") {
		t.Errorf("label %q does not carry the datacenter", labels[0])
	}
}

// Long names get elided rather than wrapped: a row wider than the terminal
// breaks the grid for every row below it.
func TestHostPickLabelsCapTheHostnameColumn(t *testing.T) {
	long := "incheon-vm-tenant-a-kubernetes-worker-gpu-new-01"
	labels := hostPickLabels(rowsFull(store.Server{Hostname: long, IP: "192.0.2.10"}))
	if strings.Contains(labels[0], long) {
		t.Errorf("label %q kept the full %d-column hostname", labels[0], lipgloss.Width(long))
	}
	if !strings.Contains(labels[0], "…") {
		t.Errorf("label %q was cut without an ellipsis", labels[0])
	}
	if w := lipgloss.Width(strings.Split(labels[0], "  ")[0]); w > hostPickNameWidth {
		t.Errorf("hostname column is %d columns, over the %d cap", w, hostPickNameWidth)
	}
}

// The hostname became optional so the commands can offer a picker. Two
// hostnames is still a mistake worth naming rather than silently ignoring the
// second.
func TestEditAndDeleteTakeAtMostOneHostname(t *testing.T) {
	for name, cmd := range map[string]*cobra.Command{
		"edit":   editCmd(),
		"delete": deleteCmd(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, args := range [][]string{nil, {"web-01"}} {
				if err := cmd.Args(cmd, args); err != nil {
					t.Errorf("%v rejected: %v", args, err)
				}
			}
			if err := cmd.Args(cmd, []string{"web-01", "web-02"}); err == nil {
				t.Error("two hostnames were accepted")
			}
		})
	}
}
