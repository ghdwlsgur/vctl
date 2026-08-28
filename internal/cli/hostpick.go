package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// resolveHost answers "which host?" — from the argument when one was given, and
// from a picker when one was not.
//
// Requiring the hostname as an argument made every edit and delete a two-step
// job: run `vctl list`, read a name off it, type it back. The names being read
// back are datacenter-prefixed VM names long enough that `vctl ssh` already
// truncates them in its own picker, so retyping is where the typo comes from.
// The inventory is loaded here anyway to check the name exists, which makes
// offering it as a list the cheaper path rather than the expensive one.
//
// Without a terminal there is no picker and no guess: a missing hostname is an
// error. That is the rule add's form already follows, and for delete it also
// stops `vctl delete` in a pipeline from resolving to whichever host happens to
// sort first.
func resolveHost(ctx context.Context, st inventoryLister, args []string, title string) (store.InventoryRow, error) {
	if len(args) > 0 {
		return findHost(ctx, st, args[0])
	}
	if !isTerminal() {
		return store.InventoryRow{}, fmt.Errorf("hostname is required when there is no terminal to pick at")
	}
	rows, err := st.ListInventory(ctx, "")
	if err != nil {
		return store.InventoryRow{}, err
	}
	return pickHost(rows, title)
}

// pickHost runs the selection itself, split from resolveHost so the empty
// inventory and the cancel path are reachable without a terminal.
//
// Rows are grouped by datacenter so ←/→ narrows the list the way it does in the
// `vctl ssh` picker. Typing filters too, but the two answer different questions:
// filtering assumes you know part of the name, and the tabs are for when what
// you know is the site.
func pickHost(rows []store.InventoryRow, title string) (store.InventoryRow, error) {
	if len(rows) == 0 {
		return store.InventoryRow{}, fmt.Errorf("the inventory is empty; register a host with vctl add")
	}
	i, err := pickIndex(hostPickLabels(rows), hostPickGroups(rows), title)
	if err != nil {
		return store.InventoryRow{}, err
	}
	return rows[i], nil
}

// hostPickGroups is the datacenter of each row, for the picker's tabs.
func hostPickGroups(rows []store.InventoryRow) *listGroups {
	of := make([]string, 0, len(rows))
	for _, r := range rows {
		of = append(of, r.DC)
	}
	return &listGroups{name: "DC", of: of}
}

// hostPickNameWidth caps the hostname column. Past this the row wraps and the
// grid stops being a grid, and the tail of these names is what distinguishes
// them, which is what ui.Truncate keeps.
const hostPickNameWidth = 40

// hostPickLabels renders one line per host on a grid computed across every row,
// so the picker's columns line up the way `vctl list` does.
//
// The label is also what type-to-filter matches against, which is why the jump
// host is spelled out rather than abbreviated: typing a bastion's name finds
// everything that reaches the network through it.
func hostPickLabels(rows []store.InventoryRow) []string {
	cells := make([][]string, 0, len(rows))
	for _, r := range rows {
		via := ""
		if r.JumpVia != "" {
			via = "via " + r.JumpVia
		}
		cells = append(cells, []string{
			ui.Truncate(r.Hostname, hostPickNameWidth),
			addrCell(r.IP, r.Port),
			r.DC,
			stateCell(r.State),
			via,
		})
	}
	w := ui.ColumnWidths(cells)
	out := make([]string, 0, len(cells))
	for _, c := range cells {
		line := ui.PadRight(c[0], w[0]) + "  " +
			ui.PadRight(c[1], w[1]) + "  " +
			ui.PadRight(c[2], w[2]) + "  " +
			ui.PadRight(c[3], w[3]) + "  " + c[4]
		out = append(out, strings.TrimRight(line, " "))
	}
	return out
}

// isTerminal reports whether there is someone to ask.
//
// Every interactive path checks this before offering a picker or a form. A
// command that falls back to guessing without a terminal is one that does
// something unattended that nobody chose — which for edit and delete is how a
// pipeline resolves to whichever host happens to sort first.
func isTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// isTerminalOut reports whether stdout is a screen rather than a pipe — the
// question a full-screen view asks before drawing, since a pipe would carry
// the drawing off to whatever is reading it.
func isTerminalOut() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}
