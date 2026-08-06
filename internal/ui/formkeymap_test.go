package ui

import (
	"slices"
	"testing"

	"github.com/charmbracelet/huh"
)

// A form has to be walkable in both directions. huh binds only shift+tab to
// "previous field", so noticing a typo one line up means finishing the form and
// running the command again. ↑ is the key everyone reaches for, and doing
// nothing reads as the form being broken rather than as a binding that was
// never made.
func TestFormKeyMapMovesBetweenTextFieldsWithArrows(t *testing.T) {
	km := FormKeyMap()
	if !slices.Contains(km.Input.Prev.Keys(), "up") {
		t.Errorf("↑ does not go back: Input.Prev = %v", km.Input.Prev.Keys())
	}
	if !slices.Contains(km.Input.Next.Keys(), "down") {
		t.Errorf("↓ does not go forward: Input.Next = %v", km.Input.Next.Keys())
	}
	// The keys that worked before must keep working. Someone with the old habit
	// should not discover the change by having it fail.
	for _, k := range []string{"shift+tab"} {
		if !slices.Contains(km.Input.Prev.Keys(), k) {
			t.Errorf("Input.Prev dropped %q: %v", k, km.Input.Prev.Keys())
		}
	}
	for _, k := range []string{"enter", "tab"} {
		if !slices.Contains(km.Input.Next.Keys(), k) {
			t.Errorf("Input.Next dropped %q: %v", k, km.Input.Next.Keys())
		}
	}
}

// One rule for the whole form: ↑/↓ always move between fields, in a Select as
// much as in an Input.
//
// This was ←/→ for selects once, because a vertical select spends ↑/↓ on its
// options and rebinding them would break the field to fix the form. Inline
// selects are the way out — huh gives them ←/→ for options and frees ↑/↓ — and
// somebody reading this form learns ↑/↓ on the Inputs above and then reaches
// the State field. Under the old map that key did nothing there.
func TestFormKeyMapMovesBetweenFieldsWithTheSameKeysEverywhere(t *testing.T) {
	km := FormKeyMap()
	for _, k := range []string{"up", "shift+tab"} {
		if !slices.Contains(km.Select.Prev.Keys(), k) {
			t.Errorf("Select.Prev is missing %q: %v", k, km.Select.Prev.Keys())
		}
	}
	for _, k := range []string{"down", "enter", "tab"} {
		if !slices.Contains(km.Select.Next.Keys(), k) {
			t.Errorf("Select.Next is missing %q: %v", k, km.Select.Next.Keys())
		}
	}
	// The options need ←/→, so field movement must not also claim them.
	for _, k := range []string{"left", "right"} {
		if slices.Contains(km.Select.Prev.Keys(), k) || slices.Contains(km.Select.Next.Keys(), k) {
			t.Errorf("%q was taken from the inline select's option navigation", k)
		}
	}
	// The whole arrangement rests on huh enabling Left/Right and disabling
	// Up/Down for an inline select, and on it matching option movement before
	// field movement. If a future version stops disabling Up/Down, ↑ starts
	// moving the option again and this map silently loses its way back.
	if def := huh.NewDefaultKeyMap(); !def.Select.Up.Enabled() || !def.Select.Down.Enabled() {
		t.Skip("huh changed its select defaults; re-derive this map from field_select.go")
	}
}

// Confirm keeps ←/→ for toggling Yes/No. `vctl delete`'s prompt is a single
// Confirm, and a left arrow that jumped fields instead of changing the answer
// would be the wrong trade on the one screen where the answer matters most.
func TestFormKeyMapLeavesConfirmToggleAlone(t *testing.T) {
	km := FormKeyMap()
	for _, k := range []string{"left", "right"} {
		if !slices.Contains(km.Confirm.Toggle.Keys(), k) {
			t.Errorf("Confirm.Toggle lost %q: %v", k, km.Confirm.Toggle.Keys())
		}
		if slices.Contains(km.Confirm.Prev.Keys(), k) || slices.Contains(km.Confirm.Next.Keys(), k) {
			t.Errorf("%q now moves fields instead of toggling the answer", k)
		}
	}
}
