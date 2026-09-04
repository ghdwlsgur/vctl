package openstack

import (
	"os"
	"testing"

	"github.com/ghdwlsgur/vctl/internal/testenv"
)

// Cmd(cmdkit.Env{}) in these tests falls back to app.New, which reads the
// environment and the user's config. They must see what CI sees, not this
// developer's shell.
func TestMain(m *testing.M) {
	testenv.Scrub()
	os.Exit(m.Run())
}
