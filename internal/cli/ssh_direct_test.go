package cli

import (
	"testing"

	"github.com/ghdwlsgur/vctl/internal/config"
)

// The "@" is what separates a direct address from an inventory name, so the
// split has to be exact: an inventory hostname never contains one, and a
// malformed address must not be mistaken for either.
func TestParseUserAtAddr(t *testing.T) {
	for _, tc := range []struct {
		in               string
		ok               bool
		user, host, port string
	}{
		{"ubuntu@192.0.2.10", true, "ubuntu", "192.0.2.10", "22"},
		{"ubuntu@192.0.2.10:2222", true, "ubuntu", "192.0.2.10", "2222"},
		{"root@host.example.internal", true, "root", "host.example.internal", "22"},
		{"ubuntu@[2001:db8::1]:2222", true, "ubuntu", "2001:db8::1", "2222"},

		// Not addresses — these must fall through to inventory resolution.
		{"sre-srv-0047", false, "", "", ""},
		{"0047", false, "", "", ""},
		{"", false, "", "", ""},
		{"@192.0.2.10", false, "", "", ""}, // no user
		{"ubuntu@", false, "", "", ""},     // no host
	} {
		ep, ok := parseUserAtAddr(tc.in)
		if ok != tc.ok {
			t.Errorf("parseUserAtAddr(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if ep.User != tc.user || ep.Host != tc.host || ep.Port != tc.port {
			t.Errorf("parseUserAtAddr(%q) = %+v, want user=%q host=%q port=%q",
				tc.in, ep, tc.user, tc.host, tc.port)
		}
	}
}

// A direct target has no inventory behind it, so the fields inventory would
// have supplied come from config — and there is deliberately no jump chain.
func TestDirectTargetUsesConfigDefaults(t *testing.T) {
	cfg := &config.Config{CARole: "sre-core", SSHDefaultUser: "ubuntu"}

	ep, ok := parseUserAtAddr("root@192.0.2.10:2222")
	if !ok {
		t.Fatal("expected a direct address")
	}
	tgt := ep.target(cfg)

	if tgt.User != "root" {
		t.Errorf("User = %q, want the user from the argument", tgt.User)
	}
	if tgt.Addr != "192.0.2.10:2222" {
		t.Errorf("Addr = %q", tgt.Addr)
	}
	if tgt.Role != "sre-core" {
		t.Errorf("Role = %q, want the configured CA role", tgt.Role)
	}
	if tgt.Jump != nil {
		t.Error("a direct target must not carry a jump chain")
	}
	if tgt.SkipDirect {
		t.Error("SkipDirect must stay false — direct is the only route available")
	}
}

// IPv6 without brackets has no port to split, so the whole thing is the host
// and the default port applies. Getting this wrong would silently truncate the
// address at the last colon.
func TestDirectTargetBareIPv6KeepsWholeAddress(t *testing.T) {
	ep, ok := parseUserAtAddr("ubuntu@2001:db8::1")
	if !ok {
		t.Fatal("expected a direct address")
	}
	if ep.Host != "2001:db8::1" || ep.Port != "22" {
		t.Fatalf("host=%q port=%q, want the full address on the default port", ep.Host, ep.Port)
	}
	if got := ep.target(&config.Config{}).Addr; got != "[2001:db8::1]:22" {
		t.Errorf("Addr = %q, want the bracketed form", got)
	}
}
