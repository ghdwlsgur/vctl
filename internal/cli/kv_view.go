package cli

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ghdwlsgur/vctl/internal/cli/internal/cmdkit"
	"github.com/ghdwlsgur/vctl/internal/ui"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// viewKVSecret is the interactive reading of a secret: the fields listed, the
// one under the cursor shown in clear, the rest masked. ↑/↓ moves the cursor
// and with it the one value on screen; enter (or c, y) copies that value to
// the clipboard; q leaves.
//
// It runs in the terminal's alternate screen, so when it exits nothing of what
// was shown stays in the scrollback — a value looked at is not a value left
// behind. That is also why a terminal gets the viewer rather than a --reveal
// print by default: the print puts every value on the screen at once and
// leaves it there.
func viewKVSecret(sec vaultc.KVSecret, in io.Reader, out io.Writer) error {
	m := newKVViewModel(sec, copyToClipboard)
	_, err := tea.NewProgram(m, tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen()).Run()
	return err
}

// kvViewerWanted decides between the viewer and the masked print: a terminal
// on both ends, and a live version with fields to look at. Piped output gets
// the print, as do --reveal, --field and -o, which the caller checks.
func kvViewerWanted(sec vaultc.KVSecret) bool {
	return cmdkit.IsTerminal() && cmdkit.IsTerminalOut() && kvViewable(sec)
}

// kvViewable reports whether there is anything for the viewer to show: string
// fields, on a version that still has its data.
func kvViewable(sec vaultc.KVSecret) bool {
	return len(sec.Data) > 0 && !sec.Destroyed && sec.DeletedAt.IsZero()
}

// clipboardFunc puts text on a clipboard and says which one. Injected so the
// model can be driven in tests without touching the machine's clipboard.
type clipboardFunc func(text string) (via string, err error)

type kvViewModel struct {
	sec    vaultc.KVSecret
	keys   []string
	cursor int
	status string
	copy   clipboardFunc
}

func newKVViewModel(sec vaultc.KVSecret, copy clipboardFunc) kvViewModel {
	return kvViewModel{sec: sec, keys: kvKeyNames(sec), copy: copy}
}

func (m kvViewModel) Init() tea.Cmd { return nil }

func (m kvViewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "q", "esc", "ctrl+c":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
			m.status = ""
		}
	case "down", "j":
		if m.cursor < len(m.keys)-1 {
			m.cursor++
			m.status = ""
		}
	case "enter", "c", "y":
		if len(m.keys) == 0 {
			break
		}
		field := m.keys[m.cursor]
		via, err := m.copy(m.sec.Data[field])
		if err != nil {
			m.status = ui.Fail("could not copy "+field) + " " + ui.Muted(err.Error())
		} else {
			m.status = ui.OK("copied "+field+" to the clipboard") + " " + ui.Muted("("+via+")")
		}
	}
	return m, nil
}

func (m kvViewModel) View() string {
	var b strings.Builder
	b.WriteString(kvHeading(m.sec) + "\n")
	b.WriteString(cmdkit.PickDimStyle.Render("↑↓ move — the row under the cursor shows its value · enter/c copy it · q quit") + "\n\n")

	width := 0
	for _, k := range m.keys {
		width = max(width, lipgloss.Width(k))
	}
	for _, k := range m.sec.NonString {
		width = max(width, lipgloss.Width(k))
	}
	for i, k := range m.keys {
		if i == m.cursor {
			b.WriteString(cmdkit.PickCursorStyle.Render("› ") + cmdkit.PickSelectedStyle.Render(ui.PadRight(k, width)) + "  " + ui.Value(m.sec.Data[k]) + "\n")
			continue
		}
		b.WriteString("  " + cmdkit.PickDimStyle.Render(ui.PadRight(k, width)) + "  " + ui.Muted(kvHidden) + "\n")
	}
	for _, k := range m.sec.NonString {
		b.WriteString("  " + cmdkit.PickDimStyle.Render(ui.PadRight(k, width)) + "  " + ui.Muted(kvNonStringNote) + "\n")
	}
	if len(m.sec.CustomMetadata) > 0 {
		b.WriteString("\n" + ui.Muted("metadata: "+joinSortedKV(m.sec.CustomMetadata)) + "\n")
	}
	if m.status != "" {
		b.WriteString("\n" + m.status + "\n")
	}
	return b.String()
}

// copyToClipboard puts text on the clipboard and says which one it reached.
// The platform's tool first — pbcopy, wl-copy, xclip, xsel, clip, whatever the
// host has — and when there is none, the terminal's own clipboard through the
// OSC 52 sequence, which is what works over SSH in the terminals that honour
// it. The text travels down a pipe or inside an escape sequence, never in an
// argument list where ps would show it.
func copyToClipboard(text string) (string, error) {
	if err := clipboard.WriteAll(text); err == nil {
		return "system clipboard", nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		return "", fmt.Errorf("no clipboard tool found (pbcopy, wl-copy, xclip, xsel) and no terminal for OSC 52")
	}
	defer tty.Close()
	if _, err := fmt.Fprintf(tty, "\x1b]52;c;%s\x07", base64.StdEncoding.EncodeToString([]byte(text))); err != nil {
		return "", err
	}
	return "terminal clipboard, OSC 52", nil
}
