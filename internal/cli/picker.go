package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// selectServer shows the scrollable, type-to-filter server picker: radio rows,
// DC tabs on ←/→, a numbered prompt when stdin isn't a TTY. It runs on the
// same list picker as every other selection in the tool (runListPicker), so
// what the caller owns is exactly what differs: the row labels and the query
// matcher. It used to own a second ~250-line copy of the whole model, and the
// two drifted the way copies do.
//
// cached marks the candidates as coming from the local snapshot, which
// suppresses the liveness column — see liveStatus.
func selectServer(cands []store.ServerWithStatus, title string, cached bool) (*store.ServerWithStatus, error) {
	if len(cands) == 0 {
		return nil, fmt.Errorf("no servers to choose from")
	}
	match := func(i int, q string) bool { return matchServer(cands[i], q) }
	i, err := cmdkit.PickIndexMatch(serverPickLabels(cands, cached), serverPickGroups(cands), match, title)
	if err != nil {
		return nil, err
	}
	return &cands[i], nil
}

// matchServer is the picker's query semantics, kept field-aware rather than
// matching the rendered label.
func matchServer(c store.ServerWithStatus, q string) bool {
	return strings.Contains(strings.ToLower(c.Hostname), q) ||
		strings.Contains(strings.ToLower(c.IP), q) ||
		strings.Contains(strings.ToLower(c.DC), q) ||
		strings.Contains(strings.ToLower(c.User), q) ||
		// Declared state is on the row, so "broken" has to find the broken hosts.
		// Whole word only, like the port: a prefix match would make "a" select
		// every active host and swallow the hostname search.
		store.StateOrActive(c.State) == q ||
		// The port is on screen, so it has to be typeable. Searching "10022" to
		// find the hosts behind that port is the reason to show it at all.
		strconv.Itoa(c.Port) == q
}

// serverPickGroups is the datacenter of each candidate, for the picker's tabs.
func serverPickGroups(cands []store.ServerWithStatus) *cmdkit.ListGroups {
	of := make([]string, 0, len(cands))
	for _, c := range cands {
		of = append(of, c.DC)
	}
	return cmdkit.NewListGroups("DC", of)
}

// serverPickNameWidth caps the hostname column, the same figure as the host
// picker's: past it the row wraps and the grid stops being a grid, and the
// tail of these names is what distinguishes them, which is what ui.Truncate
// keeps.
const serverPickNameWidth = 40

// serverPickLabels renders one line per candidate on a grid measured across
// every row. Measuring is what keeps the address column tight when every host
// is on port 22 — which is most of them — and grows it only for the lists
// where a non-default port is actually present.
func serverPickLabels(cands []store.ServerWithStatus, cached bool) []string {
	cells := make([][]string, 0, len(cands))
	for _, c := range cands {
		cells = append(cells, []string{
			ui.Truncate(c.Hostname, serverPickNameWidth),
			cmdkit.AddrCell(c.IP, c.Port),
			c.DC,
			liveStatus(c, cached),
			cmdkit.StateCell(c.State),
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
