package ui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

// A coloured cell carries escape sequences that occupy no columns. Cutting by
// runes sliced through one and left half of it on screen — measured in a VM
// listing, where a project rendered as "[38;5;24…team".
func TestTruncateKeepsEscapeSequencesWhole(t *testing.T) {
	styled := Muted("hybrid-platform-tabcloudit-mig-test")
	got := Truncate(styled, 18)

	if lipgloss.Width(got) > 18 {
		t.Errorf("width %d exceeds 18: %q", lipgloss.Width(got), got)
	}
	// Nothing that reads as a half-escape: every ESC in the result must open a
	// complete sequence.
	for i := 0; i < len(got); i++ {
		if got[i] == 0x1b {
			if escapeLen(got[i:]) == 0 {
				t.Fatalf("a cut escape survived at byte %d: %q", i, got)
			}
		}
	}
	if strings.Contains(stripEscapes(got), "[38;5;") {
		t.Errorf("escape bytes leaked into the visible text: %q", stripEscapes(got))
	}
	if !strings.Contains(stripEscapes(got), "…") {
		t.Errorf("no ellipsis in %q", stripEscapes(got))
	}
}

// Plain text keeps the behaviour every existing caller relies on.
func TestTruncateIsUnchangedForPlainText(t *testing.T) {
	if got := Truncate("abcdefghij", 5); got != "ab…ij" {
		t.Errorf("Truncate = %q, want ab…ij", got)
	}
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("Truncate widened %q", got)
	}
}

func stripEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if n := escapeLen(s[i:]); n > 0 {
			i += n
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
