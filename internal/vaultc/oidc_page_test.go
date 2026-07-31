package vaultc

import (
	"strings"
	"testing"
)

// The page has to work when window.close() is refused, which is the common
// case: browsers only honour it for script-opened windows, and this tab comes
// from `open`/`xdg-open`. If the confirmation text ever gets dropped in favour
// of relying on the close, a refused close leaves the user on a blank tab with
// no idea whether the login worked.
func TestOIDCDonePageReadsCorrectlyWhenCloseIsRefused(t *testing.T) {
	for _, want := range []string{"vctl login complete", "close this tab", "return to your terminal"} {
		if !strings.Contains(oidcDonePage, want) {
			t.Errorf("done page is missing %q: a refused close would leave nothing on screen", want)
		}
	}
	if !strings.Contains(oidcDonePage, "window.close()") {
		t.Error("done page never attempts to close the tab")
	}
	if !strings.Contains(oidcDonePage, "<!doctype html>") {
		t.Error("done page has no doctype; browsers render it in quirks mode")
	}
}
