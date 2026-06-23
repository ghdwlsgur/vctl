package syncx

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghdwlsgur/vctl/internal/store"
)

func TestSplitFields(t *testing.T) {
	cases := []struct{ in, k, v string }{
		{"Host sre-srv-0047", "Host", "sre-srv-0047"},
		{"  HostName 10.40.0.1", "HostName", "10.40.0.1"},
		{"Port=22", "Port", "22"},
		{"ProxyJump\tbastion", "ProxyJump", "bastion"},
	}
	for _, c := range cases {
		k, vals, ok := splitFields(trimLeftSpace(c.in))
		if !ok || k != c.k || vals[0] != c.v {
			t.Errorf("splitFields(%q) = (%q,%v,%v), want (%q,[%q ...],true)", c.in, k, vals, ok, c.k, c.v)
		}
	}
}

func TestParseExpandsMultiHostAndSkipsWildcards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	err := os.WriteFile(path, []byte(`
Host sre-a sre-b *
  HostName 10.40.0.1
  User ubuntu
  Port 2222
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	blocks, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("len(Parse) = %d, want 2", len(blocks))
	}
	if blocks[0].alias != "sre-a" || blocks[1].alias != "sre-b" {
		t.Fatalf("aliases = %q, %q; want sre-a, sre-b", blocks[0].alias, blocks[1].alias)
	}
	if blocks[0].hostName != "10.40.0.1" || blocks[0].user != "ubuntu" || blocks[0].port != 2222 {
		t.Fatalf("first block = %+v", blocks[0])
	}
}

func TestBuildNormalizesProxyJump(t *testing.T) {
	blocks := []hostBlock{
		{alias: "bastion", hostName: "10.40.0.10", user: "ubuntu", port: 22},
		{alias: "sre-app", hostName: "10.40.0.20", user: "ubuntu", port: 22, proxyJump: "jumpuser@bastion:2222"},
	}
	servers := BuildWithOptions(blocks, BuildOptions{Prefix: "sre", ProbeTimeout: time.Nanosecond})
	// sre-app matches the prefix; bastion is pulled in as its jump host even
	// though it doesn't match the prefix (includeJumpHosts).
	byName := map[string]store.Server{}
	for _, s := range servers {
		byName[s.Hostname] = s
	}
	if len(servers) != 2 {
		t.Fatalf("len(Build) = %d, want 2 (sre-app + jump host bastion)", len(servers))
	}
	if _, ok := byName["bastion"]; !ok {
		t.Fatalf("jump host bastion not included; got %v", servers)
	}
	if byName["sre-app"].JumpVia != "bastion" {
		t.Fatalf("JumpVia = %q, want bastion", byName["sre-app"].JumpVia)
	}
}

func TestBuildUsesConfigurableDefaults(t *testing.T) {
	blocks := []hostBlock{
		{alias: "prod-app", hostName: "172.16.8.20", port: 2222},
	}
	servers := BuildWithOptions(blocks, BuildOptions{
		Prefix:           "prod",
		DefaultUser:      "rocky",
		CARole:           "prod-core",
		ProbeTimeout:     time.Nanosecond,
		ProbeConcurrency: 4,
		DCRules: []DCRule{
			{Name: "prod-dc", Prefixes: []string{"172.16.8."}},
		},
	})
	if len(servers) != 1 {
		t.Fatalf("len(BuildWithOptions) = %d, want 1", len(servers))
	}
	if servers[0].User != "rocky" {
		t.Fatalf("User = %q, want rocky", servers[0].User)
	}
	if servers[0].CARole != "prod-core" {
		t.Fatalf("CARole = %q, want prod-core", servers[0].CARole)
	}
	if servers[0].DC != "prod-dc" {
		t.Fatalf("DC = %q, want prod-dc", servers[0].DC)
	}
}

func TestBuildOptionsClampProbeConcurrency(t *testing.T) {
	opts := BuildOptions{ProbeConcurrency: maxProbeConcurrency + 1}.withDefaults()
	if opts.ProbeConcurrency != maxProbeConcurrency {
		t.Fatalf("ProbeConcurrency = %d, want %d", opts.ProbeConcurrency, maxProbeConcurrency)
	}
}

func TestNormalizeJumpAlias(t *testing.T) {
	cases := map[string]string{
		"bastion":                  "bastion",
		"user@bastion":             "bastion",
		"user@bastion:2222":        "bastion",
		"[2001:db8::1]:2222":       "2001:db8::1",
		"user@[2001:db8::1]:2222":  "2001:db8::1",
		"user@bastion:2222,backup": "bastion",
	}
	for in, want := range cases {
		if got := normalizeJumpAlias(in); got != want {
			t.Errorf("normalizeJumpAlias(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyDC(t *testing.T) {
	cases := map[string]string{
		"10.40.0.249":   "incheon",
		"192.168.10.54": "incheon",
		"192.168.201.5": "seoul-onprem",
		"192.168.110.1": "seoul-onprem",
		"8.8.8.8":       "unknown",
	}
	for ip, want := range cases {
		if got := classifyDCWithRules(ip, DefaultDCRules()); got != want {
			t.Errorf("classifyDCWithRules(%q) = %q, want %q", ip, got, want)
		}
	}
}

// trimLeftSpace removes leading whitespace because splitFields expects trimmed input.
func trimLeftSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}
