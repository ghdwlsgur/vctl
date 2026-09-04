package testenv

import (
	"os"
	"testing"
)

func TestScrubKeepsOnlyWhatCISets(t *testing.T) {
	t.Setenv("VCTL_LOCAL_DB_DSN", "postgres://x")
	t.Setenv("VCTL_CACHE_DISABLE", "1")
	t.Setenv("VCTL_TEST_DSN", "keep")
	t.Setenv("VCTL_CONFIG", "/home/somebody/.vctl/config.yaml")
	Scrub()
	for _, k := range []string{"VCTL_LOCAL_DB_DSN", "VCTL_CACHE_DISABLE"} {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("%s survived Scrub with %q", k, v)
		}
	}
	if os.Getenv("VCTL_TEST_DSN") != "keep" {
		t.Error("VCTL_TEST_DSN was scrubbed; integration tests would silently skip")
	}
	if p := os.Getenv("VCTL_CONFIG"); p == "/home/somebody/.vctl/config.yaml" {
		t.Error("the user's config path survived")
	} else if _, err := os.Stat(p); err == nil {
		t.Errorf("VCTL_CONFIG %q exists; it must point nowhere", p)
	}
}
