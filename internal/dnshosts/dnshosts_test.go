package dnshosts

import (
	"strings"
	"testing"
)

const sampleZone = `192.168.201.12       harbor.sre.local
192.168.201.12       gitlab.sre.local
101.202.128.12       pub-k8s-master-01 ingress.prometheus.innogrid.com
`

func TestParseSkipsWhatItCannotRead(t *testing.T) {
	got := Parse(sampleZone + "# comment\nnot-an-ip something\n\n")
	if len(got) != 3 {
		t.Fatalf("parsed %d records, want 3", len(got))
	}
	if got[2].IP != "101.202.128.12" || len(got[2].Hostnames) != 2 {
		t.Errorf("multi-name line parsed as %+v", got[2])
	}
}

func TestLookupIsExact(t *testing.T) {
	if ip, ok := Lookup(sampleZone, "gitlab.sre.local"); !ok || ip != "192.168.201.12" {
		t.Errorf("lookup = %q %v", ip, ok)
	}
	// A substring is not a name: "gitlab.sre" must not answer.
	if _, ok := Lookup(sampleZone, "gitlab.sre"); ok {
		t.Error("a partial name resolved")
	}
}

func TestAddRefusesWhatWouldCorruptTheZone(t *testing.T) {
	if _, err := Add(sampleZone, "not-an-ip", "x.sre.local"); err == nil {
		t.Error("a bad address was accepted")
	}
	// A duplicate name is refused even with a different IP — the same name
	// answering from two lines is a coin flip per query.
	if _, err := Add(sampleZone, "10.0.0.9", "gitlab.sre.local"); err == nil {
		t.Error("a duplicate hostname was accepted")
	}
	out, err := Add(sampleZone, "192.168.201.140", "new.sre.local")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "192.168.201.140      new.sre.local\n") {
		t.Errorf("the new record is not the last line:\n%s", out)
	}
	// The lines that were there are untouched, byte for byte.
	if !strings.HasPrefix(out, sampleZone) {
		t.Error("adding a record rewrote existing lines")
	}
}

func TestRemoveKeepsTheRestOfAMultiNameLine(t *testing.T) {
	out, ok := Remove(sampleZone, "pub-k8s-master-01")
	if !ok {
		t.Fatal("nothing removed")
	}
	if _, found := Lookup(out, "pub-k8s-master-01"); found {
		t.Error("the removed name still answers")
	}
	if ip, found := Lookup(out, "ingress.prometheus.innogrid.com"); !found || ip != "101.202.128.12" {
		t.Error("the surviving name on the same line was lost")
	}
	// Removing the only name on a line removes the line.
	out, _ = Remove(out, "harbor.sre.local")
	if strings.Contains(out, "harbor") {
		t.Errorf("an empty line survived:\n%s", out)
	}
	if _, ok := Remove(sampleZone, "absent.sre.local"); ok {
		t.Error("removing an absent name claimed success")
	}
}

const sampleCorefile = `sre.local:53 {
    hosts /etc/coredns/hosts/sre.hosts {
        ttl 60
        fallthrough
    }
    log
}

innogrid.com:53 {
    hosts /etc/coredns/hosts/innogrid.hosts {
        fallthrough
    }
}

.:53 {
    hosts /etc/coredns/hosts/misc.hosts {
        fallthrough
    }
    forward . 1.1.1.1
}
`

// The Corefile is the authority on which file serves which zone — the binding
// holds because a server block says so, not because the names rhyme.
func TestZoneBindingsComeFromTheCorefile(t *testing.T) {
	b := ZoneBindings(sampleCorefile)
	want := map[string]string{"sre.local": "sre.hosts", "innogrid.com": "innogrid.hosts", ".": "misc.hosts"}
	for z, key := range want {
		if b[z] != key {
			t.Errorf("zone %q → %q, want %q", z, b[z], key)
		}
	}
}

func TestZoneKeyForMatchesTheLongestSuffix(t *testing.T) {
	b := map[string]string{"sre.local": "sre.hosts", "innogrid.com": "innogrid.hosts", ".": "misc.hosts"}
	for _, tc := range []struct{ host, zone, key string }{
		{"vault.sre.local", "sre.local", "sre.hosts"},
		{"gitlab.innogrid.com", "innogrid.com", "innogrid.hosts"},
		// Not a suffix match on the string: presre.local is a different name.
		{"presre.local", ".", "misc.hosts"},
		{"grafana.hwabul-saas.com", ".", "misc.hosts"},
	} {
		if zone, key := ZoneKeyFor(tc.host, b); zone != tc.zone || key != tc.key {
			t.Errorf("ZoneKeyFor(%q) = (%q, %q), want (%q, %q)", tc.host, zone, key, tc.zone, tc.key)
		}
	}
}

// The renderer must reproduce the repo Makefile's `make sync` output exactly:
// one format, two writers, or a vctl commit and a hand sync fight forever.
func TestRenderMatchesTheMakeSyncFormat(t *testing.T) {
	got := RenderConfigMapYAML(map[string]string{
		"sre.hosts":      "192.168.201.12       vault.sre.local\n",
		"innogrid.hosts": "192.168.190.101      harbor.innogrid.com\n",
		"misc.hosts":     "10.0.0.1             x.example.com\n",
	})
	want := `# ============================================================
# ConfigMap: coredns-hosts
# API가 수정하는 대상 — 레코드 추가/삭제/조회
# 키 이름 = 파일명으로 /etc/coredns/hosts/ 에 마운트됨
# ============================================================
apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-hosts
  namespace: dns-system
  labels:
    app.kubernetes.io/name: coredns
    app.kubernetes.io/component: dns-records
data:
  innogrid.hosts: |
    192.168.190.101      harbor.innogrid.com

  sre.hosts: |
    192.168.201.12       vault.sre.local

  misc.hosts: |
    10.0.0.1             x.example.com
`
	if got != want {
		t.Errorf("rendered file differs from make sync's format:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
