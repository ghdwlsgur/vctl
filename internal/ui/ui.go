package ui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type KV struct {
	Key   string
	Value string
	State State
}

type State int

const (
	StatePlain State = iota
	StateOK
	StateWarn
	StateFail
)

var (
	accent = lipgloss.Color("39")
	green  = lipgloss.Color("42")
	yellow = lipgloss.Color("214")
	red    = lipgloss.Color("203")
	muted  = lipgloss.Color("245")

	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(accent)
	labelStyle  = lipgloss.NewStyle().Foreground(muted)
	valueStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(muted)
	okStyle     = lipgloss.NewStyle().Bold(true).Foreground(green)
	warnStyle   = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	failStyle   = lipgloss.NewStyle().Bold(true).Foreground(red)
	mutedStyle  = lipgloss.NewStyle().Foreground(muted)
)

func Title(s string) string { return titleStyle.Render(s) }
func Muted(s string) string { return mutedStyle.Render(s) }
func Value(s string) string { return valueStyle.Render(s) }

func OK(s string) string   { return okStyle.Render(s) }
func Warn(s string) string { return warnStyle.Render(s) }
func Fail(s string) string { return failStyle.Render(s) }

func Section(w io.Writer, title string) {
	fmt.Fprintln(w, Title(title))
}

func Successf(w io.Writer, format string, args ...interface{}) {
	fmt.Fprintf(w, "%s %s\n", OK("OK"), fmt.Sprintf(format, args...))
}

func Warnf(w io.Writer, format string, args ...interface{}) {
	fmt.Fprintf(w, "%s %s\n", Warn("WARN"), fmt.Sprintf(format, args...))
}

func Errorf(w io.Writer, format string, args ...interface{}) {
	fmt.Fprintf(w, "%s %s\n", Fail("ERR"), fmt.Sprintf(format, args...))
}

func Infof(w io.Writer, format string, args ...interface{}) {
	fmt.Fprintf(w, "%s %s\n", Muted("--"), fmt.Sprintf(format, args...))
}

func Badge(state State, text string) string {
	switch state {
	case StateOK:
		return OK(text)
	case StateWarn:
		return Warn(text)
	case StateFail:
		return Fail(text)
	default:
		return Value(text)
	}
}

func KVs(w io.Writer, rows []KV) {
	width := 0
	for _, row := range rows {
		if n := lipgloss.Width(row.Key); n > width {
			width = n
		}
	}
	for _, row := range rows {
		key := padRight(labelStyle.Render(row.Key), width)
		fmt.Fprintf(w, "%s  %s\n", key, Badge(row.State, row.Value))
	}
}

func Table(w io.Writer, headers []string, rows [][]string) error {
	if len(headers) == 0 {
		return nil
	}
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = lipgloss.Width(header)
	}
	for _, row := range rows {
		for i := range headers {
			if i >= len(row) {
				continue
			}
			if n := lipgloss.Width(row[i]); n > widths[i] {
				widths[i] = n
			}
		}
	}

	styledHeaders := make([]string, len(headers))
	for i, header := range headers {
		styledHeaders[i] = headerStyle.Render(strings.ToUpper(header))
	}
	if _, err := fmt.Fprintln(w, joinPadded(styledHeaders, widths)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, mutedStyle.Render(joinRule(widths))); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(w, joinPadded(row, widths)); err != nil {
			return err
		}
	}
	return nil
}

func joinPadded(cells []string, widths []int) string {
	out := make([]string, len(widths))
	for i := range widths {
		cell := ""
		if i < len(cells) {
			cell = cells[i]
		}
		out[i] = padRight(cell, widths[i])
	}
	return strings.Join(out, "  ")
}

func joinRule(widths []int) string {
	parts := make([]string, len(widths))
	for i, width := range widths {
		parts[i] = strings.Repeat("-", width)
	}
	return strings.Join(parts, "  ")
}

func padRight(s string, width int) string {
	pad := width - lipgloss.Width(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// Truncate shortens s to at most max columns, eliding the middle with "…" so the
// head and tail both stay visible. Long hostnames (e.g.
// incheon-vm-[surromind]-…-worker-gpu-new) keep their common prefix and the
// distinguishing suffix instead of overflowing the column and wrapping the row.
func Truncate(s string, max int) string {
	if max <= 1 || lipgloss.Width(s) <= max {
		return s
	}
	r := []rune(s)
	keep := max - 1 // room for the ellipsis
	head := (keep + 1) / 2
	tail := keep - head
	return string(r[:head]) + "…" + string(r[len(r)-tail:])
}
