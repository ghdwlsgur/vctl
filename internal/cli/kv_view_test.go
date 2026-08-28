package cli

import (
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

func keyPress(s string) tea.KeyMsg {
	switch s {
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func viewAfter(t *testing.T, m tea.Model, keys ...string) kvViewModel {
	t.Helper()
	for _, k := range keys {
		m, _ = m.Update(keyPress(k))
	}
	return m.(kvViewModel)
}

// One value on screen at a time: the row under the cursor, in clear; every
// other row masked. Moving the cursor moves the one value.
func TestKVViewShowsOnlyTheRowUnderTheCursor(t *testing.T) {
	m := newKVViewModel(sampleSecret(), func(string) (string, error) { return "test", nil })

	text := ui.StripANSI(m.View())
	if !strings.Contains(text, "token-field-value") || strings.Contains(text, "someone") {
		t.Errorf("first row should show token and mask username:\n%s", text)
	}
	if !strings.Contains(text, kvHidden) || !strings.Contains(text, "retries") || !strings.Contains(text, "owner=sre") {
		t.Errorf("mask, non-string field and metadata missing:\n%s", text)
	}

	text = ui.StripANSI(viewAfter(t, m, "down").View())
	if strings.Contains(text, "token-field-value") || !strings.Contains(text, "someone") {
		t.Errorf("after ↓ the second row should show username and mask token:\n%s", text)
	}
}

func TestKVViewCursorStaysInsideTheList(t *testing.T) {
	m := newKVViewModel(sampleSecret(), nil)
	if got := viewAfter(t, m, "up", "up").cursor; got != 0 {
		t.Errorf("↑ at the top moved the cursor to %d", got)
	}
	if got := viewAfter(t, m, "down", "down", "down", "j").cursor; got != 1 {
		t.Errorf("↓ past the end moved the cursor to %d, want 1 (two fields)", got)
	}
}

// enter copies the value under the cursor — that value, not the first one —
// and says so, naming the field rather than showing the value again.
func TestKVViewCopiesTheValueUnderTheCursor(t *testing.T) {
	var copied string
	m := newKVViewModel(sampleSecret(), func(s string) (string, error) { copied = s; return "test board", nil })
	after := viewAfter(t, m, "down", "enter")
	if copied != "someone" {
		t.Fatalf("copied %q, want the username under the cursor", copied)
	}
	status := ui.StripANSI(after.View())
	if !strings.Contains(status, "copied username to the clipboard") || !strings.Contains(status, "test board") {
		t.Errorf("status missing:\n%s", status)
	}
	// c and y are the same key for people who reach for them.
	copied = ""
	viewAfter(t, m, "c")
	if copied != "token-field-value" {
		t.Errorf("c copied %q", copied)
	}
}

func TestKVViewReportsAClipboardThatIsNotThere(t *testing.T) {
	m := newKVViewModel(sampleSecret(), func(string) (string, error) { return "", errors.New("no clipboard tool found") })
	text := ui.StripANSI(viewAfter(t, m, "enter").View())
	if !strings.Contains(text, "could not copy token") || !strings.Contains(text, "no clipboard tool") {
		t.Errorf("failure not reported:\n%s", text)
	}
}

func TestKVViewQuitsOnQ(t *testing.T) {
	m := newKVViewModel(sampleSecret(), nil)
	for _, k := range []string{"q", "esc"} {
		_, cmd := m.Update(keyPress(k))
		if cmd == nil {
			t.Errorf("%s did not quit", k)
			continue
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("%s returned %T, want tea.QuitMsg", k, cmd())
		}
	}
}

// A version with nothing to show is not worth a screen: the masked print says
// why (deleted, destroyed, no fields) and the viewer is skipped.
func TestKVViewableNeedsALiveVersionWithFields(t *testing.T) {
	live := sampleSecret()
	if !kvViewable(live) {
		t.Error("a live secret with fields is not viewable")
	}
	deleted := sampleSecret()
	deleted.DeletedAt = time.Now()
	destroyed := sampleSecret()
	destroyed.Destroyed = true
	empty := sampleSecret()
	empty.Data = nil
	for name, sec := range map[string]vaultc.KVSecret{"deleted": deleted, "destroyed": destroyed, "empty": empty} {
		if kvViewable(sec) {
			t.Errorf("%s version reported viewable", name)
		}
	}
}
