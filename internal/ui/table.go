package ui

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Column describes one piece of a responsive table. Required columns stay on
// screen; optional columns disappear from highest Priority to lowest when the
// terminal is narrow. MinWidth and MaxWidth are display columns, not bytes.
type Column struct {
	Header     string
	MinWidth   int
	MaxWidth   int
	Optional   bool
	Priority   int
	AlignRight bool
}

// TableOptions controls presentation without making callers calculate layout.
// Width zero uses the terminal width. A non-terminal writer keeps every column
// and value, which is important when output is redirected for inspection.
type TableOptions struct {
	Width  int
	Indent string
}

// TableGroup is a titled set of rows sharing one responsive column layout.
type TableGroup struct {
	Title string
	Meta  string
	Rows  [][]string
}

// ResponsiveTable renders a table that drops optional columns and truncates
// retained cells only when a terminal width requires it.
func ResponsiveTable(w io.Writer, columns []Column, rows [][]string, options TableOptions) error {
	if len(columns) == 0 {
		return nil
	}
	width := options.Width
	if width <= 0 {
		width = terminalWidth(w)
	}
	layout := fitTable(columns, rows, width, lipgloss.Width(options.Indent))
	return renderTableLayout(w, columns, rows, layout, options.Indent)
}

// GroupedTable renders operational groups with a repeated header. All groups
// share one layout so the same field remains in the same visual column while a
// reader scans down the fleet.
func GroupedTable(w io.Writer, columns []Column, groups []TableGroup, options TableOptions) error {
	allRows := make([][]string, 0)
	for _, group := range groups {
		allRows = append(allRows, group.Rows...)
	}
	width := options.Width
	if width <= 0 {
		width = terminalWidth(w)
	}
	layout := fitTable(columns, allRows, width, lipgloss.Width(options.Indent))
	for i, group := range groups {
		if i > 0 {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		heading := titleStyle.Render("▌ " + group.Title)
		if group.Meta != "" {
			heading += " " + mutedStyle.Render("· "+group.Meta)
		}
		if _, err := fmt.Fprintln(w, heading); err != nil {
			return err
		}
		if err := renderTableLayout(w, columns, group.Rows, layout, options.Indent); err != nil {
			return err
		}
	}
	return nil
}

type tableLayout struct {
	indexes []int
	widths  []int
}

func fitTable(columns []Column, rows [][]string, maxWidth, indent int) tableLayout {
	indexes := make([]int, len(columns))
	widths := make([]int, len(columns))
	for i, column := range columns {
		indexes[i] = i
		widths[i] = lipgloss.Width(column.Header)
		for _, row := range rows {
			if i < len(row) && lipgloss.Width(row[i]) > widths[i] {
				widths[i] = lipgloss.Width(row[i])
			}
		}
		if maxWidth > 0 && column.MaxWidth > 0 && widths[i] > column.MaxWidth {
			widths[i] = column.MaxWidth
		}
	}
	if maxWidth <= 0 {
		return tableLayout{indexes: indexes, widths: widths}
	}

	optional := make([]int, 0)
	for i, column := range columns {
		if column.Optional {
			optional = append(optional, i)
		}
	}
	sort.SliceStable(optional, func(i, j int) bool {
		return columns[optional[i]].Priority > columns[optional[j]].Priority
	})
	for _, drop := range optional {
		if tableWidth(indexes, widths, indent) <= maxWidth {
			break
		}
		indexes = withoutIndex(indexes, drop)
	}

	shrinkTo := func(minimum func(int) int) {
		for tableWidth(indexes, widths, indent) > maxWidth {
			widest := -1
			for _, index := range indexes {
				if widths[index] > minimum(index) && (widest < 0 || widths[index] > widths[widest]) {
					widest = index
				}
			}
			if widest < 0 {
				return
			}
			widths[widest]--
		}
	}
	shrinkTo(func(index int) int {
		if columns[index].MinWidth > 0 {
			return columns[index].MinWidth
		}
		return lipgloss.Width(columns[index].Header)
	})
	// Extremely narrow terminals still get one visible column per required
	// field instead of wrapping past the promised width.
	shrinkTo(func(int) int { return 1 })
	return tableLayout{indexes: indexes, widths: widths}
}

func tableWidth(indexes, widths []int, indent int) int {
	if len(indexes) == 0 {
		return indent
	}
	total := indent + 2*(len(indexes)-1)
	for _, index := range indexes {
		total += widths[index]
	}
	return total
}

func withoutIndex(indexes []int, drop int) []int {
	out := indexes[:0]
	for _, index := range indexes {
		if index != drop {
			out = append(out, index)
		}
	}
	return out
}

func renderTableLayout(w io.Writer, columns []Column, rows [][]string, layout tableLayout, indent string) error {
	head := make([]string, len(layout.indexes))
	rule := make([]string, len(layout.indexes))
	displayWidths := make([]int, len(layout.indexes))
	for i, index := range layout.indexes {
		displayWidths[i] = layout.widths[index]
		head[i] = headerStyle.Render(strings.ToUpper(Truncate(columns[index].Header, displayWidths[i])))
		rule[i] = strings.Repeat("─", displayWidths[i])
	}
	if _, err := fmt.Fprintln(w, indent+joinSelected(head, displayWidths, nil)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, indent+mutedStyle.Render(strings.Join(rule, "  "))); err != nil {
		return err
	}
	for _, row := range rows {
		cells := make([]string, len(layout.indexes))
		right := make([]bool, len(layout.indexes))
		for i, index := range layout.indexes {
			if index < len(row) {
				cells[i] = Truncate(row[index], layout.widths[index])
			}
			right[i] = columns[index].AlignRight
		}
		if _, err := fmt.Fprintln(w, strings.TrimRight(indent+joinSelected(cells, displayWidths, right), " ")); err != nil {
			return err
		}
	}
	return nil
}

func joinSelected(cells []string, widths []int, right []bool) string {
	out := make([]string, len(cells))
	for i, cell := range cells {
		pad := widths[i] - lipgloss.Width(cell)
		if pad < 0 {
			pad = 0
		}
		if right != nil && right[i] {
			out[i] = strings.Repeat(" ", pad) + cell
		} else {
			out[i] = cell + strings.Repeat(" ", pad)
		}
	}
	return strings.Join(out, "  ")
}
