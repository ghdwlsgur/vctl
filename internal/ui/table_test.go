package ui

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

type closedTableWriter struct{}

func (closedTableWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestResponsiveTableKeepsEssentialColumnsWithinTerminalWidth(t *testing.T) {
	columns := []Column{
		{Header: "host", MinWidth: 12, MaxWidth: 24},
		{Header: "agent", MinWidth: 5, MaxWidth: 9},
		{Header: "state", MinWidth: 5, MaxWidth: 8, Optional: true, Priority: 2},
		{Header: "address", MinWidth: 12, MaxWidth: 21},
		{Header: "user", MinWidth: 4, MaxWidth: 10, Optional: true, Priority: 3},
		{Header: "via", MinWidth: 8, MaxWidth: 18},
	}
	rows := [][]string{{
		"a-very-long-inventory-hostname", "stale 57d", "maintenance",
		"192.168.201.105:12022", "sre-admin", "a-long-bastion-hostname",
	}}

	var out bytes.Buffer
	if err := ResponsiveTable(&out, columns, rows, TableOptions{Width: 68, Indent: "  "}); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	for _, want := range []string{"HOST", "AGENT", "ADDRESS", "VIA"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("responsive table dropped essential column %q:\n%s", want, rendered)
		}
	}
	for _, dropped := range []string{"STATE", "USER", "maintenance", "sre-admin"} {
		if strings.Contains(rendered, dropped) {
			t.Errorf("responsive table kept optional value %q at narrow width:\n%s", dropped, rendered)
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(rendered, "\n"), "\n") {
		if width := lipgloss.Width(line); width > 68 {
			t.Errorf("line width %d exceeds 68: %q", width, line)
		}
	}
}

func TestGroupedTableRepeatsHeadersForEachOperationalGroup(t *testing.T) {
	columns := []Column{{Header: "host"}, {Header: "status"}}
	groups := []TableGroup{
		{Title: "incheon", Meta: "2 hosts", Rows: [][]string{{"host-a", "up"}, {"host-b", "up"}}},
		{Title: "seoul", Meta: "1 host", Rows: [][]string{{"host-c", "stale"}}},
	}

	var out bytes.Buffer
	if err := GroupedTable(&out, columns, groups, TableOptions{Width: 80, Indent: "  "}); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	if count := strings.Count(rendered, "HOST"); count != 2 {
		t.Fatalf("header count = %d, want one per group:\n%s", count, rendered)
	}
	for _, want := range []string{"▌ incheon", "· 2 hosts", "▌ seoul", "· 1 host"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("grouped table missing %q:\n%s", want, rendered)
		}
	}
}

func TestResponsiveTableReturnsOutputFailures(t *testing.T) {
	err := ResponsiveTable(closedTableWriter{}, []Column{{Header: "host"}}, [][]string{{"host-a"}}, TableOptions{})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("error = %v, want closed pipe", err)
	}
}
