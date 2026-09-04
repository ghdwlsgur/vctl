package dnshosts

import (
	"strings"
	"testing"
)

const sampleZone = `192.0.2.10           harbor.example.com
192.0.2.10           gitlab.example.com
198.51.100.20        k8s-master-01 ingress.metrics.example.com
`

func TestParseSkipsWhatItCannotRead(t *testing.T) {
	got := Parse(sampleZone + "# comment\nnot-an-ip something\n\n")
	if len(got) != 3 {
		t.Fatalf("parsed %d records, want 3", len(got))
	}
	if got[2].IP != "198.51.100.20" || len(got[2].Hostnames) != 2 {
		t.Errorf("multi-name line parsed as %+v", got[2])
	}
}

func TestLookupIsExact(t *testing.T) {
	if ip, ok := Lookup(sampleZone, "gitlab.example.com"); !ok || ip != "192.0.2.10" {
		t.Errorf("lookup = %q %v", ip, ok)
	}
	// A substring is not a name: "gitlab.exam" must not answer.
	if _, ok := Lookup(sampleZone, "gitlab.exam"); ok {
		t.Error("a partial name resolved")
	}
}

func TestAddRefusesWhatWouldCorruptTheZone(t *testing.T) {
	if _, err := Add(sampleZone, "not-an-ip", "x.example.com"); err == nil {
		t.Error("a bad address was accepted")
	}
	// A duplicate name is refused even with a different IP — the same name
	// answering from two lines is a coin flip per query.
	if _, err := Add(sampleZone, "10.0.0.9", "gitlab.example.com"); err == nil {
		t.Error("a duplicate hostname was accepted")
	}
	out, err := Add(sampleZone, "192.0.2.40", "new.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out, "192.0.2.40           new.example.com\n") {
		t.Errorf("the new record is not the last line:\n%s", out)
	}
	// The lines that were there are untouched, byte for byte.
	if !strings.HasPrefix(out, sampleZone) {
		t.Error("adding a record rewrote existing lines")
	}
}

func TestRemoveKeepsTheRestOfAMultiNameLine(t *testing.T) {
	out, ok := Remove(sampleZone, "k8s-master-01")
	if !ok {
		t.Fatal("nothing removed")
	}
	if _, found := Lookup(out, "k8s-master-01"); found {
		t.Error("the removed name still answers")
	}
	if ip, found := Lookup(out, "ingress.metrics.example.com"); !found || ip != "198.51.100.20" {
		t.Error("the surviving name on the same line was lost")
	}
	// Removing the only name on a line removes the line.
	out, _ = Remove(out, "harbor.example.com")
	if strings.Contains(out, "harbor") {
		t.Errorf("an empty line survived:\n%s", out)
	}
	if _, ok := Remove(sampleZone, "absent.example.com"); ok {
		t.Error("removing an absent name claimed success")
	}
}

const sampleCorefile = `corp.internal:53 {
    hosts /etc/coredns/hosts/corp.hosts {
        ttl 60
        fallthrough
    }
    log
}

example.com:53 {
    hosts /etc/coredns/hosts/example.hosts {
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
	want := map[string]string{"corp.internal": "corp.hosts", "example.com": "example.hosts", ".": "misc.hosts"}
	for z, key := range want {
		if b[z] != key {
			t.Errorf("zone %q → %q, want %q", z, b[z], key)
		}
	}
}

func TestZoneKeyForMatchesTheLongestSuffix(t *testing.T) {
	b := map[string]string{"corp.internal": "corp.hosts", "example.com": "example.hosts", ".": "misc.hosts"}
	for _, tc := range []struct{ host, zone, key string }{
		{"vault.corp.internal", "corp.internal", "corp.hosts"},
		{"gitlab.example.com", "example.com", "example.hosts"},
		// Not a suffix match on the string: precorp.internal is a different name.
		{"precorp.internal", ".", "misc.hosts"},
		{"grafana.other.example.org", ".", "misc.hosts"},
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
		"sre.hosts":      "192.0.2.10           vault.corp.internal\n",
		"innogrid.hosts": "192.0.2.11           harbor.example.com\n",
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
    192.0.2.11           harbor.example.com

  sre.hosts: |
    192.0.2.10           vault.corp.internal

  misc.hosts: |
    10.0.0.1             x.example.com
`
	if got != want {
		t.Errorf("rendered file differs from make sync's format:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// Parse is the inverse of Render on Render's own output: a write path reads the
// repo file back into the map it will edit, so any drift between the two would
// corrupt a round-trip. Also checks a multi-name line, an empty zone, and an
// extra (non-canonical) key survive the trip.
func TestParseRenderRoundTrip(t *testing.T) {
	data := map[string]string{
		"sre.hosts":      "192.0.2.10           vault.corp.internal\n192.0.2.10           gitlab.corp.internal\n",
		"innogrid.hosts": "192.0.2.11           a.example.com b.example.com\n",
		"misc.hosts":     "",
		"extra.hosts":    "10.0.0.1             x.example.com\n",
	}
	rendered := RenderConfigMapYAML(data)
	got, err := ParseConfigMapYAML(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(data) {
		t.Fatalf("round-trip changed the key set: %v", got)
	}
	for k, v := range data {
		if got[k] != v {
			t.Errorf("key %q: round-trip gave %q, want %q", k, got[k], v)
		}
	}
	// And Render is stable across the trip — the byte output is identical, so a
	// vctl commit of unchanged data produces no diff.
	if RenderConfigMapYAML(got) != rendered {
		t.Error("Render(Parse(Render(x))) != Render(x)")
	}
}

// A hostname that only appears inside a comment is not a record: rm must not
// rewrite or drop the comment line.
func TestRemoveLeavesCommentsAlone(t *testing.T) {
	text := "192.0.2.10           real.example.com\n# 192.0.2.99 ghost.example.com\n"
	out, ok := Remove(text, "ghost.example.com")
	if ok {
		t.Error("claimed to remove a name that only appears in a comment")
	}
	if out != text {
		t.Errorf("the comment was altered:\n%s", out)
	}
}

// The stored line uses the canonical address, so a mixed-case or non-compressed
// IPv6 add is found by a later lookup and verified against the same spelling.
func TestAddCanonicalizesIPv6(t *testing.T) {
	out, err := Add("", "2001:DB8::0:1", "v6.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ip, _ := Lookup(out, "v6.example.com"); ip != "2001:db8::1" {
		t.Errorf("stored address = %q, want canonical 2001:db8::1", ip)
	}
}

// A repo file an operator reformatted by hand still reads as the records it
// holds. The shapes here are all valid YAML for the same content; a parser
// that only knew Render's exact output would read each as an empty zone, and
// the write path would then commit and project a file with the records gone.
func TestParseReadsHandEditedShapesAsTheSameRecords(t *testing.T) {
	want := map[string]string{
		"sre.hosts":      "192.0.2.10           vault.corp.internal\n",
		"innogrid.hosts": "192.0.2.11           harbor.example.com\n",
		"misc.hosts":     "",
	}
	handEdited := `apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns-hosts
  namespace: dns-system
data:
  "sre.hosts": |-
    192.0.2.10           vault.corp.internal
  innogrid.hosts: |+
    192.0.2.11           harbor.example.com

  misc.hosts: ""
`
	got, err := ParseConfigMapYAML(handEdited)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q: %q, want %q", k, got[k], v)
		}
	}
	// And rendering it produces the canonical file — the commit normalises
	// the hand edit instead of preserving it.
	if RenderConfigMapYAML(got) != RenderConfigMapYAML(want) {
		t.Error("a hand-edited file did not render canonically")
	}
}

// Only the coredns-hosts ConfigMap is edited. Another object at the same path
// — a renamed file, a different resource — is refused, not read as a zone map.
func TestParseRefusesAnotherObject(t *testing.T) {
	for name, doc := range map[string]string{
		"a Secret":          "kind: Secret\nmetadata:\n  name: coredns-hosts\n  namespace: dns-system\ndata:\n  sre.hosts: x\n",
		"another ConfigMap": "kind: ConfigMap\nmetadata:\n  name: coredns-corefile\n  namespace: dns-system\ndata: {}\n",
		"another namespace": "kind: ConfigMap\nmetadata:\n  name: coredns-hosts\n  namespace: default\ndata: {}\n",
		"not yaml":          "{{{",
	} {
		if _, err := ParseConfigMapYAML(doc); err == nil {
			t.Errorf("%s was accepted as the hosts ConfigMap", name)
		}
	}
}

func TestRecordCountSpansEveryZone(t *testing.T) {
	n := RecordCount(map[string]string{
		"a.hosts": "192.0.2.1 x.example.com\n192.0.2.2 y.example.com z.example.com\n",
		"b.hosts": "# only a comment\n",
		"c.hosts": "192.0.2.3 w.example.com\n",
	})
	if n != 3 {
		t.Errorf("RecordCount = %d, want 3 (lines, not names)", n)
	}
}
