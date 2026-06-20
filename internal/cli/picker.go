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
func selectServer(cands []store.Server, title string) (*store.Server, error) {
	if len(cands) == 0 {
		return nil, fmt.Errorf("no servers to choose from")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return numberPick(cands, title)
	}

	options := make([]huh.Option[int], len(cands))
	for i, c := range cands {
		status := "down"
		if c.LastSeenUp != nil {
			status = "up"
		}
		label := fmt.Sprintf("%-30s %-16s %-12s %s", c.Hostname, c.IP, c.DC, status)
		options[i] = huh.NewOption(label, i)
	}

	var idx int
	err := huh.NewSelect[int]().
		Title(title).
		Options(options...).
		Height(18).      // viewport; longer lists scroll
		Filtering(true). // type to filter
		Value(&idx).
		Run()
	if err != nil {
		return nil, fmt.Errorf("selection cancelled: %w", err)
	}
	return &cands[idx], nil
}

// numberPick is the non-TTY fallback (pipes/CI): a plain numbered prompt.
func numberPick(cands []store.Server, title string) (*store.Server, error) {
	ui.Section(os.Stderr, title)
	for i, c := range cands {
		up := ui.Muted("down")
		if c.LastSeenUp != nil {
			up = ui.OK("up")
		}
		fmt.Fprintf(os.Stderr, "  %2d  %-28s %-16s %-12s %s\n", i+1, c.Hostname, c.IP, c.DC, up)
	}
	fmt.Fprint(os.Stderr, ui.Muted("number: "))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(cands) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &cands[n-1], nil
}
