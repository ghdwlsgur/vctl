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

// Select uses ↑/↓ to choose an option. Rebinding those to move between fields
// would break the field in order to fix the form, so it gets ←/→ — which huh
// leaves unbound on vertical selects.
func TestFormKeyMapLeavesSelectVerticalKeysAlone(t *testing.T) {
	km := FormKeyMap()
	for _, k := range []string{"up", "down"} {
		if slices.Contains(km.Select.Prev.Keys(), k) || slices.Contains(km.Select.Next.Keys(), k) {
			t.Errorf("%q was taken from the select's option navigation", k)
		}
	}
	if !slices.Contains(km.Select.Prev.Keys(), "left") {
		t.Errorf("← does not leave a select: Select.Prev = %v", km.Select.Prev.Keys())
	}
	if !slices.Contains(km.Select.Next.Keys(), "right") {
		t.Errorf("→ does not leave a select: Select.Next = %v", km.Select.Next.Keys())
	}
	// huh disables Left/Right on vertical selects, which is what makes them free
	// to take. If a future version enables them, this binding starts fighting the
	// field and the fix is to pick different keys.
	if def := huh.NewDefaultKeyMap(); def.Select.Left.Enabled() || def.Select.Right.Enabled() {
		t.Error("huh now binds ←/→ inside selects; Select.Prev/Next need different keys")
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
