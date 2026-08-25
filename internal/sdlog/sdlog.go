// Package sdlog writes the diagnostic lines a daemon owes its journal.
//
// The node agent printed its warnings through internal/ui — the terminal
// styling package, pulled into a systemd service for two printf helpers — and
// journald received the lines without a priority, so `journalctl -p warning`
// could not find the warnings among the heartbeats. When systemd owns the
// stream it says so ($JOURNAL_STREAM); each line then carries the sd-daemon
// <N> prefix journald parses into PRIORITY. Anywhere else — a terminal, a
// pipe, a test — the level is spelled out as a word, uncolored: a daemon's
// stderr is a log, not a screen.
package sdlog

import (
	"fmt"
	"io"
	"os"
)

// Logger writes leveled lines to one stream.
type Logger struct {
	w        io.Writer
	journald bool
}

// New builds a logger for w, detecting whether systemd owns this process's
// output. The detection is process-wide ($JOURNAL_STREAM), which fits the
// daemons this exists for: the journal either owns their stderr or nothing
// does.
func New(w io.Writer) *Logger {
	return &Logger{w: w, journald: os.Getenv("JOURNAL_STREAM") != ""}
}

// Syslog priorities, as sd-daemon(3) spells them.
const (
	prioWarn = "<4>"
	prioInfo = "<6>"
)

func (l *Logger) Warnf(format string, args ...any) { l.logf(prioWarn, "WARN", format, args...) }
func (l *Logger) Infof(format string, args ...any) { l.logf(prioInfo, "--", format, args...) }

func (l *Logger) logf(prio, word, format string, args ...any) {
	if l.journald {
		fmt.Fprintf(l.w, prio+format+"\n", args...)
		return
	}
	fmt.Fprintf(l.w, word+" "+format+"\n", args...)
}
