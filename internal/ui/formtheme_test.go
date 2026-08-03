package ui

import (
	"testing"

	"github.com/charmbracelet/huh"
)

// The form theme has to use the same palette the rest of vctl renders with.
// A form library brings its own colours by default, and the mismatch is
// invisible in review: nobody chose it, and it only shows when someone runs
// the command.
func TestFormThemeUsesTheSamePaletteAsTheRestOfTheCLI(t *testing.T) {
	th := FormTheme()

	// accent (39) drives titles and selection across list/ip/wg output.
	if got := th.Focused.Title.GetForeground(); got != accent {
		t.Errorf("form title colour = %v, want the CLI accent %v", got, accent)
	}
	// Errors must match ui.Fail, or a rejected value reads as two unrelated
	// failures — one from the form, one from the command.
	if got := th.Focused.ErrorMessage.GetForeground(); got != red {
		t.Errorf("form error colour = %v, want ui.Fail's %v", got, red)
	}
	if got := th.Focused.Description.GetForeground(); got != muted {
		t.Errorf("form description colour = %v, want ui.Muted's %v", got, muted)
	}
}

// The theme must actually differ from huh's default, or this file is decoration.
// Comparing the base theme's title colour to ours is the check that would catch
// someone dropping the customisation while keeping the function.
//
// The assertion is on the style, not on rendered output: lipgloss strips ANSI
// when stdout is not a terminal, so a render-based check passes vacuously in
// CI — which is the opposite of what a colour test should do.
func TestFormThemeDiffersFromHuhDefault(t *testing.T) {
	if FormTheme().Focused.Title.GetForeground() == huh.ThemeBase().Focused.Title.GetForeground() {
		t.Error("form theme title matches huh's default; the customisation is gone")
	}
}
