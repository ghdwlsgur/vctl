// Package testenv makes a test process see what CI sees. A developer's shell
// carries VCTL_* overrides and a user config file — a static local DSN, a
// preferred login, cache knobs — and any test that reaches app.New through
// cmdkit.Env's fallback would otherwise run against them: a WARN about a
// static Postgres credential in the middle of a unit test was the symptom.
package testenv

import (
	"os"
	"path/filepath"
	"strings"
)

// Scrub removes the developer's vctl environment from the process. It is for
// TestMain, before m.Run: every VCTL_* variable is unset except VCTL_TEST_*
// (integration tests key off those, and CI sets them on purpose), and
// VCTL_CONFIG is pointed at a file that does not exist so the user's config is
// not read either.
func Scrub() {
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "VCTL_") && !strings.HasPrefix(k, "VCTL_TEST_") {
			os.Unsetenv(k)
		}
	}
	// A path that cannot exist: the temp dir is real, the name is not.
	os.Setenv("VCTL_CONFIG", filepath.Join(os.TempDir(), "vctl-testenv-no-config", "config.yaml"))
}
