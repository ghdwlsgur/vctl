package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// TimeLayout is the local timestamp layout shared by audit/session output.
const TimeLayout = "2006-01-02 15:04:05"

// CompactDuration renders d as a single largest-unit value (e.g. "5s", "3m",
// "2h", "4d") for at-a-glance "last seen" columns.
func CompactDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// TruncateTail shortens s to at most max columns by dropping the tail and adding
// "…" as "...". Unlike Truncate (which elides the middle), it keeps the leading
// text — for free-form fields like command args where the start matters most.
func TruncateTail(s string, max int) string {
	const suffix = "..."
	r := []rune(s)
	if max <= 0 || len(r) <= max {
		return s
	}
	if max <= len(suffix) {
		return string(r[:max])
	}
	return string(r[:max-len(suffix)]) + suffix
}

type KV struct {
	Key   string
	Value string
	State State
	// Raw, when set, is printed verbatim as the value instead of Badge(State,
	// Value) — for values that carry their own styling (e.g. an embedded Bar)
	// that must not be re-wrapped. State still drives the leading dot.
	Raw string
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

// Dot returns a status glyph carrying the state color: a filled ● for ok/warn
// (green/yellow), a hollow ○ for fail (red), and a blank for plain rows so
// dotted and undotted lines still align. It is the shared liveness glyph used
// across list, the ssh picker, status, and the audit result column.
func Dot(state State) string {
	switch state {
	case StateOK:
		return okStyle.Render("●")
	case StateWarn:
		return warnStyle.Render("●")
	case StateFail:
		return failStyle.Render("○")
	default:
		return " "
	}
}

// OrDash returns s, or a muted "-" when s is empty, for table cells where a
// blank would read as missing data rather than "not set".
func OrDash(s string) string {
	if s == "" {
		return mutedStyle.Render("-")
	}
	return s
}

// Bar renders a fixed-width coverage meter (done/total) as filled/empty blocks,
// e.g. "████████░░░░". The filled portion is green, the remainder muted.
func Bar(done, total, width int) string {
	if width <= 0 {
		return ""
	}
	filled := 0
	if total > 0 {
		filled = done * width / total
	}
	if filled > width {
		filled = width
	}
	return okStyle.Render(strings.Repeat("█", filled)) + mutedStyle.Render(strings.Repeat("░", width-filled))
}

// Ago renders a muted "(3m ago)" relative time for pairing next to an absolute
// timestamp. Returns "" for a zero time.
func Ago(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return mutedStyle.Render("(" + CompactDuration(time.Since(t)) + " ago)")
}

// Section prints a section header. On a terminal it renders the picker-style
// "▌ title ────" rule filling the line; when the writer is not a terminal
// (pipes, logs, CI) it prints just "▌ title" so redirected output stays clean.
func Section(w io.Writer, title string) {
	head := titleStyle.Render("▌ " + title)
	if cols := terminalWidth(w); cols > 0 {
		if rule := cols - lipgloss.Width(head) - 1; rule > 0 {
			fmt.Fprintln(w, head+" "+mutedStyle.Render(strings.Repeat("─", rule)))
			return
		}
	}
	fmt.Fprintln(w, head)
}

// terminalWidth returns the column count when w is a terminal, else 0.
func terminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0
	}
	cols, _, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0
	}
	return cols
}

// logf writes a tagged status line; the four level helpers differ only by tag.
func logf(w io.Writer, tag, format string, args ...any) {
	fmt.Fprintf(w, "%s %s\n", tag, fmt.Sprintf(format, args...))
}

func Successf(w io.Writer, format string, args ...any) { logf(w, OK("OK"), format, args...) }
func Warnf(w io.Writer, format string, args ...any)    { logf(w, Warn("WARN"), format, args...) }
func Errorf(w io.Writer, format string, args ...any)   { logf(w, Fail("ERR"), format, args...) }
func Infof(w io.Writer, format string, args ...any)    { logf(w, Muted("--"), format, args...) }

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
		key := PadRight(labelStyle.Render(row.Key), width)
		val := row.Raw
		if val == "" {
			val = Badge(row.State, row.Value)
		}
		fmt.Fprintf(w, "%s  %s %s\n", key, Dot(row.State), val)
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
		out[i] = PadRight(cell, widths[i])
	}
	return strings.Join(out, "  ")
}

func joinRule(widths []int) string {
	parts := make([]string, len(widths))
	for i, width := range widths {
		parts[i] = strings.Repeat("─", width)
	}
	return strings.Join(parts, "  ")
}

// PadRight right-pads s with spaces to width display columns, measuring with
// lipgloss.Width so ANSI styling and wide runes are counted correctly. Returns s
// unchanged when it already meets or exceeds width.
func PadRight(s string, width int) string {
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
