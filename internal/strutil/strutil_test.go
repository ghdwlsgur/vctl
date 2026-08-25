package strutil

import (
	"strings"
	"testing"
)

// Vault and the OpenStack SDK return errors several lines long. Dropping one
// into a key/value row breaks the alignment for every row after it, which is
// how a diagnostic becomes harder to read than the log it replaced.
func TestOneLineFlattensMultiLineErrors(t *testing.T) {
	in := "no credentials (Error making API request.\n\nURL: GET https://x\nCode: 403\n)"
	got := OneLine(in)
	if strings.Contains(got, "\n") {
		t.Errorf("OneLine left a newline: %q", got)
	}
	for _, want := range []string{"403", "https://x"} {
		if !strings.Contains(got, want) {
			t.Errorf("OneLine dropped %q: %q", want, got)
		}
	}
}
