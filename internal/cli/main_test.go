package cli

import (
	"os"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/testenv"
)

// Several tests here build a command tree with cmdkit.Env{} and let it fall
// back to app.New, which reads the environment and the user's config. They
// must see what CI sees, not this developer's shell.
func TestMain(m *testing.M) {
	testenv.Scrub()
	os.Exit(m.Run())
}
