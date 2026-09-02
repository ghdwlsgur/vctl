package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every Select in this package has to be inline, and this reads the source to
// check it because nothing at runtime can.
//
// ui.FormKeyMap gives Select the same ↑/↓ as Input so one rule holds for a
// whole form. That only works on an inline select: huh matches option movement
// before field movement and enables Up/Down for a vertical select, so a
// vertical one under this map would spend ↑/↓ on its options and have no
// arrow key left to go back with. The person filling in the form would learn
// ↑/↓ on the fields above, reach the select, press ↑ and get nothing — which is
// the bug this arrangement was introduced to fix.
//
// A source scan is crude, and it is still the only thing that fails when
// somebody adds huh.NewSelect without Inline(true) two years from now.
func TestEverySelectIsInline(t *testing.T) {
	// The whole command tree, not just this directory: the rule holds for the
	// packages the tree was split into (cmdkit, openstack) the same as here.
	var files []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".go") {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(body), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "huh.NewSelect[") {
				continue
			}
			// The builder chain runs until the statement ends. Ten lines is more
			// than any of these take and short enough not to run into the next.
			end := min(i+10, len(lines))
			if !strings.Contains(strings.Join(lines[i:end], "\n"), "Inline(true)") {
				t.Errorf("%s:%d: a Select without Inline(true) — under ui.FormKeyMap "+
					"this field cannot be left with an arrow key", name, i+1)
			}
		}
	}
}
