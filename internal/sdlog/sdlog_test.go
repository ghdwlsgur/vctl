package sdlog

import (
	"bytes"
	"testing"
)

// Under the journal every line carries the priority prefix journald parses
// into PRIORITY; anywhere else the level is a word. The prefix is the whole
// point — without it `journalctl -p warning` reads a warning as info.
func TestJournalGetsPrioritiesTerminalGetsWords(t *testing.T) {
	t.Setenv("JOURNAL_STREAM", "8:2650574")
	var buf bytes.Buffer
	j := New(&buf)
	j.Warnf("disk at %d%%", 91)
	j.Infof("reported")
	if got := buf.String(); got != "<4>disk at 91%\n<6>reported\n" {
		t.Fatalf("journald lines = %q", got)
	}

	t.Setenv("JOURNAL_STREAM", "")
	buf.Reset()
	p := New(&buf)
	p.Warnf("disk at %d%%", 91)
	p.Infof("reported")
	if got := buf.String(); got != "WARN disk at 91%\n-- reported\n" {
		t.Fatalf("plain lines = %q", got)
	}
}
