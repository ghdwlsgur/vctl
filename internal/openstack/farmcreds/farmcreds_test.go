package farmcreds

import (
	"strings"
	"testing"
)

// A colon in a Vault path is legal but awkward everywhere it is then typed.
// The port still has to survive: two deployments can share an address.
func TestKeyIsTypeableAndKeepsThePort(t *testing.T) {
	got := Key("172.16.0.245:5000")
	// The prefix is shared with everything else the team stores there.
	if !strings.HasPrefix(got, "vctl-") {
		t.Errorf("key = %q, want the vctl- prefix that keeps these apart", got)
	}
	if strings.Contains(got, ":") {
		t.Errorf("key = %q, still carries a colon", got)
	}
	if !strings.Contains(got, "5000") {
		t.Errorf("key = %q, lost the port — two deployments can share an address", got)
	}
	if Key("10.0.0.1:5000") == Key("10.0.0.1:5001") {
		t.Error("two ports on one address collapsed into one key")
	}
}
