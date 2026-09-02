package cmdkit

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// press sends one key to the model and hands the model back, so a test can read
// like the sequence an operator types.
func press(m listModel, t tea.KeyType) listModel {
	next, _ := m.Update(tea.KeyMsg{Type: t})
	return next.(listModel)
}

func visibleLabels(m listModel) []string {
	out := make([]string, 0, len(m.filtered))
	for _, i := range m.filtered {
		out = append(out, m.cands[i])
	}
	return out
}

// ←/→ narrows to one group, the way it does in the `vctl ssh` picker. Typing
// filters too, but the two answer different questions: filtering assumes you
// know part of the name, and the tabs are for when what you know is the site.
func TestListPickerFiltersByGroupWithLeftAndRight(t *testing.T) {
	items := []string{"seoul-a", "seoul-b", "incheon-a"}
	g := NewListGroups("DC", []string{"seoul", "seoul", "incheon"})
	m := newListModel(items, g, nil, "pick", false)
	m.width = 80

	if got := len(m.filtered); got != 3 {
		t.Fatalf("the first tab shows %d rows, want all 3", got)
	}
	if !strings.Contains(m.View(), "all DCs") {
		t.Errorf("the tab row does not say every group is shown:\n%s", m.View())
	}

	// Tabs are sorted with "" first, so → lands on incheon, then seoul.
	m = press(m, tea.KeyRight)
	if got := visibleLabels(m); len(got) != 1 || got[0] != "incheon-a" {
		t.Errorf("after → the rows are %v, want just incheon-a", got)
	}
	if view := m.View(); !strings.Contains(view, "DC ‹ incheon ›") {
		t.Errorf("the tab row does not name the group:\n%s", view)
	}
	m = press(m, tea.KeyRight)
	if got := visibleLabels(m); len(got) != 2 {
		t.Errorf("after a second → the rows are %v, want the two seoul hosts", got)
	}
	// Wrapping back to "all" makes the control reversible without counting how
	// many times it was pressed.
	m = press(m, tea.KeyRight)
	if got := len(m.filtered); got != 3 {
		t.Errorf("→ past the last group shows %d rows, want all 3", got)
	}
	m = press(m, tea.KeyLeft)
	if got := visibleLabels(m); len(got) != 2 {
		t.Errorf("← from all shows %v, want the last group", got)
	}
}

// A picker with nothing to group by must not grow a control that does nothing.
// One group covering every row is the same case: cycling between "all" and
// "all, named" moves no rows.
func TestListPickerHidesTheTabRowWithoutGroups(t *testing.T) {
	for name, g := range map[string]*ListGroups{
		"none": nil,
		"one":  {name: "DC", of: []string{"seoul", "seoul"}},
	} {
		t.Run(name, func(t *testing.T) {
			m := newListModel([]string{"a", "b"}, g, nil, "pick", false)
			m.width = 80
			if view := m.View(); strings.Contains(view, "‹") {
				t.Errorf("a tab row was drawn:\n%s", view)
			}
			if got := len(press(m, tea.KeyRight).filtered); got != 2 {
				t.Errorf("→ changed the rows to %d, want both still shown", got)
			}
		})
	}
}

// The list picker and the server picker are both "choose one of these", and an
// operator meets them one after another — `vctl ssh` to reach a host, then
// `vctl delete` to retire it. Different marks for the same gesture read as two
// different tools, and nobody chose that; it is just what happens when the two
// pickers are written separately.
func TestListPickerMarksTheCursorLikeTheServerPicker(t *testing.T) {
	m := newListModel([]string{"web-01", "web-02"}, nil, nil, "pick", false)
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
	m := newListModel([]string{"alice", "bob"}, nil, nil, "pick", true)
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
			m := newListModel([]string{"aaa", "bbb", "ccc"}, nil, nil, "pick", multi)
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
