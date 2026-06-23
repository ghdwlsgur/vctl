package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/ui"
)

// selectServer shows a pretty, arrow-key driven picker (charmbracelet/huh) with
// type-to-filter. Falls back to a numbered prompt when stdin isn't a TTY (pipes, CI).
func selectServer(cands []store.ServerWithStatus, title string) (*store.ServerWithStatus, error) {
	if len(cands) == 0 {
		return nil, fmt.Errorf("no servers to choose from")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return numberPick(cands, title)
	}

	options := make([]huh.Option[int], len(cands))
	for i, c := range cands {
		// liveStatusText (not LastSeenUp alone) so the picker agrees with `vctl list`.
		label := fmt.Sprintf("%-40s %-16s %-12s %s", ui.Truncate(c.Hostname, 40), c.IP, c.DC, liveStatusText(c))
		options[i] = huh.NewOption(label, i)
	}

	// The list shows truncated labels (long VM names would wrap and break the
	// layout). DescriptionFunc re-evaluates as the cursor moves — huh updates the
	// bound idx on every up/down — so the focused row's FULL name and details show
	// below the list without widening every row.
	var idx int
	err := huh.NewSelect[int]().
		Title(title).
		Options(options...).
		Height(18).      // viewport; longer lists scroll
		Filtering(true). // type to filter
		DescriptionFunc(func() string {
			if idx < 0 || idx >= len(cands) {
				return ""
			}
			c := cands[idx]
			return fmt.Sprintf("%s  (%s@%s · %s · %s)", c.Hostname, c.User, c.IP, c.DC, liveStatusText(c))
		}, &idx).
		Value(&idx).
		Run()
	if err != nil {
		return nil, fmt.Errorf("selection cancelled: %w", err)
	}
	return &cands[idx], nil
}

// numberPick is the non-TTY fallback (pipes/CI): a plain numbered prompt.
func numberPick(cands []store.ServerWithStatus, title string) (*store.ServerWithStatus, error) {
	ui.Section(os.Stderr, title)
	for i, c := range cands {
		fmt.Fprintf(os.Stderr, "  %2d  %-28s %-16s %-12s %s\n", i+1, c.Hostname, c.IP, c.DC, liveStatus(c))
	}
	fmt.Fprint(os.Stderr, ui.Muted("number: "))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(cands) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &cands[n-1], nil
}
