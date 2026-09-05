package cli

import (
	"strings"
	"testing"
)

// Ids carry their kind on purpose; these are the shapes the CLI must accept
// and the mistakes it must catch before anything reaches the database.
func TestValidateNetEntityID(t *testing.T) {
	cases := []struct {
		kind, id string
		ok       bool
	}{
		{"site", "site/a", true},
		{"farm", "farm/x", true},
		{"physical-host", "host/h1", true},
		{"vm", "vm/gw-1", true},
		{"tunnel", "tunnel/gw/wg0", true},
		{"edge", "edge/fw-1", true},
		{"egress", "egress/198.51.100.1", true},
		{"network", "net/x/tenant", true},

		{"network", "net/tenant", false}, // farm segment is not optional
		{"network", "net/x/", false},     // empty name
		{"vm", "host/h1", false},         // kind and prefix disagree
		{"farm", "farm/", false},         // empty name
		{"router", "router/r1", false},   // unknown kind
	}
	for _, c := range cases {
		err := validateNetEntityID(c.kind, c.id)
		if c.ok && err != nil {
			t.Errorf("%s %q: unexpected error %v", c.kind, c.id, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s %q: expected rejection", c.kind, c.id)
		}
	}
}

// Flags give strings, JSON gives structure, JSON wins on collision — that is
// the whole contract of the two attribute inputs.
func TestParseAttrs(t *testing.T) {
	attrs, err := parseAttrs(
		[]string{"cidr=192.0.2.0/24", "method=direct"},
		`{"oif":["ens3","ens4"],"method":"proxy"}`,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attrs["cidr"] != "192.0.2.0/24" {
		t.Errorf("flag attr lost: %#v", attrs)
	}
	if attrs["method"] != "proxy" {
		t.Errorf("JSON should win on collision, got %#v", attrs["method"])
	}
	oif, ok := attrs["oif"].([]any)
	if !ok || len(oif) != 2 {
		t.Errorf("structured JSON attr lost: %#v", attrs["oif"])
	}

	if _, err := parseAttrs([]string{"novalue"}, ""); err == nil {
		t.Errorf("expected rejection of --attr without '='")
	}
	if _, err := parseAttrs(nil, `{not json`); err == nil || !strings.Contains(err.Error(), "attrs-json") {
		t.Errorf("expected --attrs-json parse error, got %v", err)
	}
}

func TestAttrsSummaryIsStableAndCompact(t *testing.T) {
	if got := attrsSummary(nil); got != "-" {
		t.Errorf("empty attrs should render as dash, got %q", got)
	}
	got := attrsSummary(map[string]any{"b": 2, "a": "x"})
	if got != "a=x b=2" {
		t.Errorf("summary should be key-sorted, got %q", got)
	}
}
