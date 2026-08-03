package cli

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// The list picker and the server picker are both "choose one of these", and an
// operator meets them one after another — `vctl ssh` to reach a host, then
// `vctl delete` to retire it. Different marks for the same gesture read as two
// different tools, and nobody chose that; it is just what happens when the two
// pickers are written separately.
func TestListPickerMarksTheCursorLikeTheServerPicker(t *testing.T) {
	m := newListModel([]string{"web-01", "web-02"}, "pick", false)
	m.width = 80
	view := m.View()
	if !strings.Contains(view, "› ● web-01") {
		t.Errorf("cursor row is not marked with a filled dot:\n%s", view)
	}
	if !strings.Contains(view, "  ○ web-02") {
		t.Errorf("unselected row is not marked with an empty dot:\n%s", view)
	}
}

// Multi-select keeps checkboxes: the question there is "which of these", and a
// row can be on without the cursor sitting on it, which a radio dot cannot say.
func TestListPickerKeepsCheckboxesInMultiSelect(t *testing.T) {
	m := newListModel([]string{"alice", "bob"}, "pick", true)
	m.width = 80
	if view := m.View(); !strings.Contains(view, "[ ] alice") {
		t.Errorf("unchecked row is not a checkbox:\n%s", view)
	}
	m.selected[0] = true
	if view := m.View(); !strings.Contains(view, "[x] alice") {
		t.Errorf("checked row is not marked:\n%s", view)
	}
}

// Marks have to be the same width within a mode or the labels stop lining up
// row to row, which is the whole point of computing the column grid.
func TestListPickerMarksShareAWidth(t *testing.T) {
	for name, multi := range map[string]bool{"single": false, "multi": true} {
		t.Run(name, func(t *testing.T) {
			m := newListModel([]string{"aaa", "bbb", "ccc"}, "pick", multi)
			m.width = 80
			if multi {
				m.selected[1] = true
			}
			// Display columns, not bytes: the marks are multibyte runes, so
			// strings.Index would report the ASCII rows as starting earlier.
			var offsets []int
			for _, line := range strings.Split(m.View(), "\n") {
				for _, label := range []string{"aaa", "bbb", "ccc"} {
					if i := strings.Index(line, label); i >= 0 {
						offsets = append(offsets, lipgloss.Width(line[:i]))
					}
				}
			}
			if len(offsets) != 3 {
				t.Fatalf("found %d rows, want 3", len(offsets))
			}
			for _, o := range offsets[1:] {
				if o != offsets[0] {
					t.Errorf("labels start at %v; the rows do not line up", offsets)
					break
				}
			}
		})
	}
}
