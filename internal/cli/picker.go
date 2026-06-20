package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

<<<<<<< HEAD
	"github.com/charmbracelet/huh"
=======
>>>>>>> ef91f76e8271aa6bc48803ceafefb2e39228e8de
	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/store"
)

<<<<<<< HEAD
// selectServer shows a pretty, arrow-key driven picker (charmbracelet/huh) with
// type-to-filter. Falls back to a numbered prompt when stdin isn't a TTY (pipes, CI).
=======
// ANSI helpers (kept tiny; no external TUI dependency).
const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiReverse = "\x1b[7m"
	ansiGreen   = "\x1b[32m"
	ansiCyan    = "\x1b[36m"
	ansiYellow  = "\x1b[33m"
)

const pickerWindow = 14 // max rows shown at once (scrolls beyond this)

// selectServer shows an interactive, arrow-key driven picker with type-to-filter.
// Falls back to a numbered prompt when stdin isn't a TTY (pipes, CI).
>>>>>>> ef91f76e8271aa6bc48803ceafefb2e39228e8de
func selectServer(cands []store.Server, title string) (*store.Server, error) {
	if len(cands) == 0 {
		return nil, fmt.Errorf("no servers to choose from")
	}
<<<<<<< HEAD
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return numberPick(cands, title)
	}

	options := make([]huh.Option[int], len(cands))
	for i, c := range cands {
		status := "·"
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
=======
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return numberPick(cands, title)
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return numberPick(cands, title)
	}
	defer term.Restore(fd, old)

	query := ""
	cursor := 0
	offset := 0
	prevLines := 0
	in := os.Stdin

	for {
		filtered := filterServers(cands, query)
		if cursor >= len(filtered) {
			cursor = len(filtered) - 1
		}
		if cursor < 0 {
			cursor = 0
		}
		// keep cursor within the visible window
		if cursor < offset {
			offset = cursor
		}
		if cursor >= offset+pickerWindow {
			offset = cursor - pickerWindow + 1
		}
		prevLines = renderPicker(title, filtered, cursor, offset, query, prevLines)

		b := make([]byte, 3)
		n, rerr := in.Read(b)
		if rerr != nil || n == 0 {
			clearPicker(prevLines)
			return nil, fmt.Errorf("selection aborted")
		}
		switch {
		case b[0] == 3 || b[0] == 'q' && query == "": // Ctrl-C / q (when not filtering)
			clearPicker(prevLines)
			return nil, fmt.Errorf("cancelled")
		case b[0] == 13 || b[0] == 10: // Enter
			if len(filtered) == 0 {
				continue
			}
			clearPicker(prevLines)
			sel := filtered[cursor]
			return &sel, nil
		case b[0] == 0x1b && n >= 3 && b[1] == '[': // arrow keys
			switch b[2] {
			case 'A':
				cursor--
			case 'B':
				cursor++
			}
		case b[0] == 0x1b && n == 1: // bare ESC
			clearPicker(prevLines)
			return nil, fmt.Errorf("cancelled")
		case b[0] == 127 || b[0] == 8: // Backspace
			if query != "" {
				query = query[:len(query)-1]
				cursor = 0
				offset = 0
			}
		case n == 1 && b[0] == 'k': // vim up
			cursor--
		case n == 1 && b[0] == 'j': // vim down
			cursor++
		case n == 1 && b[0] >= 0x20 && b[0] < 0x7f: // printable → filter
			query += string(b[0])
			cursor = 0
			offset = 0
		}
	}
}

func filterServers(cands []store.Server, q string) []store.Server {
	if q == "" {
		return cands
	}
	ql := strings.ToLower(q)
	out := make([]store.Server, 0, len(cands))
	for _, c := range cands {
		if strings.Contains(strings.ToLower(c.Hostname), ql) ||
			strings.Contains(strings.ToLower(c.IP), ql) ||
			strings.Contains(strings.ToLower(c.DC), ql) {
			out = append(out, c)
		}
	}
	return out
}

// renderPicker draws the list and returns the number of lines printed.
func renderPicker(title string, list []store.Server, cursor, offset int, query string, prevLines int) int {
	var b strings.Builder
	if prevLines > 0 {
		fmt.Fprintf(&b, "\x1b[%dA", prevLines) // move cursor up to redraw in place
	}
	clearLine := "\x1b[2K\r"

	fmt.Fprintf(&b, "%s%s%s", clearLine, ansiBold, title)
	if query != "" {
		fmt.Fprintf(&b, "  %s/%s%s", ansiCyan, query, ansiReset)
	}
	b.WriteString(ansiReset + "\r\n")
	lines := 1

	end := offset + pickerWindow
	if end > len(list) {
		end = len(list)
	}
	for i := offset; i < end; i++ {
		c := list[i]
		status, scolor := "·", ansiDim
		if c.LastSeenUp != nil {
			status, scolor = "up", ansiGreen
		}
		row := fmt.Sprintf("%-30s %-16s %-12s [%s%s%s]",
			c.Hostname, c.IP, c.DC, scolor, status, ansiReset)
		if i == cursor {
			fmt.Fprintf(&b, "%s%s ▸ %s%s\r\n", clearLine, ansiReverse, row, ansiReset)
		} else {
			fmt.Fprintf(&b, "%s   %s\r\n", clearLine, row)
		}
		lines++
	}
	// footer
	fmt.Fprintf(&b, "%s%s ↑/↓ move · type to filter · enter select · esc cancel  (%d/%d)%s\r\n",
		clearLine, ansiDim, cursor+1, len(list), ansiReset)
	lines++

	fmt.Fprint(os.Stderr, b.String())
	return lines
}

func clearPicker(lines int) {
	if lines <= 0 {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\x1b[%dA", lines)
	for i := 0; i < lines; i++ {
		b.WriteString("\x1b[2K\r")
		if i < lines-1 {
			b.WriteString("\x1b[1B")
		}
	}
	fmt.Fprintf(&b, "\x1b[%dA", lines-1)
	fmt.Fprint(os.Stderr, b.String())
}

// numberPick is the non-TTY fallback (pipes/CI): original numbered prompt.
>>>>>>> ef91f76e8271aa6bc48803ceafefb2e39228e8de
func numberPick(cands []store.Server, title string) (*store.Server, error) {
	fmt.Fprintln(os.Stderr, title)
	for i, c := range cands {
		up := "·"
		if c.LastSeenUp != nil {
			up = "up"
		}
		fmt.Fprintf(os.Stderr, "  %2d) %-28s %-16s %-12s [%s]\n", i+1, c.Hostname, c.IP, c.DC, up)
	}
	fmt.Fprint(os.Stderr, "number: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || n < 1 || n > len(cands) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &cands[n-1], nil
}
