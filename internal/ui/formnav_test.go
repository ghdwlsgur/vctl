package ui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
)

// focusedTitle reports which field carries huh's focus bar.
func focusedTitle(v string) string {
	for line := range strings.SplitSeq(v, "\n") {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "┃") {
			return strings.TrimSpace(strings.TrimPrefix(s, "┃"))
		}
	}
	return "(none)"
}

// runCmd executes a command, giving up on the ones that are timers.
//
// The cursor's blink command sleeps for half a second before returning, and a
// focus change batches one alongside the message this test is waiting for.
// Running them all in series makes every keystroke here cost 530ms of nothing.
// The message that moves focus is produced immediately, so a short deadline
// separates the two without needing to identify either — huh's message types
// are unexported.
func runCmd(c tea.Cmd) tea.Msg {
	ch := make(chan tea.Msg, 1)
	go func() { ch <- c() }()
	select {
	case v := <-ch:
		return v
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

// send delivers a key and then runs the commands the model returns, feeding
// their messages back.
//
// This has to drive the command loop, not just call Update: huh moves focus by
// *returning* a NextField/PrevField command rather than by mutating state, so a
// test that only calls Update sees the focus never move — including for huh's
// own default keys. Two rounds is what a focus change costs.
func send(m tea.Model, msg tea.Msg) tea.Model {
	for depth := 0; depth < 2 && msg != nil; depth++ {
		var cmd tea.Cmd
		m, cmd = m.Update(msg)
		if cmd == nil {
			return m
		}
		msg = nil
		next := runCmd(cmd)
		if batch, ok := next.(tea.BatchMsg); ok {
			for _, c := range batch {
				if c == nil {
					continue
				}
				if v := runCmd(c); v != nil {
					msg = v
				}
			}
			continue
		}
		msg = next
	}
	return m
}

func navForm() tea.Model {
	a, b, c := "", "", ""
	f := huh.NewForm(huh.NewGroup(
		huh.NewInput().Title("First").Value(&a),
		huh.NewInput().Title("Second").Value(&b),
		huh.NewInput().Title("Third").Value(&c),
	)).WithTheme(FormTheme()).WithKeyMap(FormKeyMap()).WithWidth(60)
	f.Init()
	return f
}

// The complaint this fixes: press enter, go down, and there is no way back up.
// Asserting on the bindings alone would not catch it — the binding can be
// present and still lose to something huh checks first — so this drives the
// form and reads which field the focus bar ends on.
func TestFormArrowKeysWalkTheFormBothWays(t *testing.T) {
	m := navForm()
	if got := focusedTitle(m.View()); got != "First" {
		t.Fatalf("form opens focused on %q, want First", got)
	}

	m = send(m, tea.KeyMsg{Type: tea.KeyDown})
	if got := focusedTitle(m.View()); got != "Second" {
		t.Fatalf("↓ moved focus to %q, want Second", got)
	}
	m = send(m, tea.KeyMsg{Type: tea.KeyDown})
	if got := focusedTitle(m.View()); got != "Third" {
		t.Fatalf("↓ again moved focus to %q, want Third", got)
	}

	// The part that did not work before.
	m = send(m, tea.KeyMsg{Type: tea.KeyUp})
	if got := focusedTitle(m.View()); got != "Second" {
		t.Fatalf("↑ moved focus to %q, want Second — the form is still one-way", got)
	}
	m = send(m, tea.KeyMsg{Type: tea.KeyUp})
	if got := focusedTitle(m.View()); got != "First" {
		t.Errorf("↑ again moved focus to %q, want First", got)
	}
	// Nothing precedes the first field, so ↑ there has to stay put rather than
	// wrap to the end or leave the form.
	m = send(m, tea.KeyMsg{Type: tea.KeyUp})
	if got := focusedTitle(m.View()); got != "First" {
		t.Errorf("↑ on the first field moved to %q, want to stay on First", got)
	}
}

// enter and tab kept working. Someone with the old habit should not find out
// about the change by having it fail.
func TestFormKeepsEnterAndTabMovingForward(t *testing.T) {
	for name, k := range map[string]tea.KeyType{"enter": tea.KeyEnter, "tab": tea.KeyTab} {
		t.Run(name, func(t *testing.T) {
			m := send(navForm(), tea.KeyMsg{Type: k})
			if got := focusedTitle(m.View()); got != "Second" {
				t.Errorf("%s moved focus to %q, want Second", name, got)
			}
		})
	}
}

// The help line is the only place the new keys are announced. A binding nobody
// is told about is discoverable only by guessing.
func TestFormHelpAnnouncesTheArrowKeys(t *testing.T) {
	m := send(navForm(), tea.KeyMsg{Type: tea.KeyDown})
	view := m.View()
	for _, want := range []string{"↑", "back", "next"} {
		if !strings.Contains(view, want) {
			t.Errorf("the help line does not mention %q:\n%s", want, view)
		}
	}
}
