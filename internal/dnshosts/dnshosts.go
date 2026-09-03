// Package dnshosts owns the hosts-file dialect the fleet's DNS records live
// in, and the shape of the two places one record exists: the coredns-hosts
// ConfigMap CoreDNS serves from, and the IaC repo's configmap-hosts.yaml that
// records the same content in git.
//
// vctl writes through both — git first, because the repo is the source of
// truth an ArgoCD sync would reassert, then the live ConfigMap so the record
// answers without waiting for anyone to sync. Keeping the two byte-compatible
// is this package's job: the YAML renderer below reproduces the repo
// Makefile's `make sync` output exactly, so a vctl commit and a hand sync
// produce the same file.
package dnshosts

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
)

// Record is one line of a hosts file: an address and the names that answer
// with it.
type Record struct {
	IP        string
	Hostnames []string
}

// Parse reads hosts-file text. Unparseable lines are skipped rather than
// fatal: this reads content that operators also edit by hand, and one stray
// line must not make the whole zone unlistable.
func Parse(text string) []Record {
	var out []Record
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if _, err := netip.ParseAddr(fields[0]); err != nil {
			continue
		}
		out = append(out, Record{IP: fields[0], Hostnames: fields[1:]})
	}
	return out
}

// Lookup finds the address a hostname answers with, by exact match.
func Lookup(text, hostname string) (string, bool) {
	for _, r := range Parse(text) {
		if slices.Contains(r.Hostnames, hostname) {
			return r.IP, true
		}
	}
	return "", false
}

// Add appends one record line. The caller has already decided the zone; this
// only guards what would corrupt the file or contradict it: a bad address, or
// a hostname the zone already answers for (possibly with a different IP —
// the caller reports which).
//
// Always a new line rather than appended to an existing line with the same
// IP: the files in production carry one service per line on purpose, and the
// minimal diff is what makes the git history readable.
func Add(text, ip, hostname string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", fmt.Errorf("%q is not an IP address", ip)
	}
	// The canonical form, so the stored line, the duplicate check, and the
	// post-write verification all compare the same string — 2001:DB8::1 and
	// 2001:db8::1 are one address, and a hosts file that carried both spellings
	// would answer a query twice.
	ip = addr.String()
	// A control character other than the ones Fields splits on would survive
	// into a line that then reparses as two tokens; reject the whole class.
	if hostname == "" || strings.ContainsAny(hostname, " \t\n\r\v\f#") {
		return "", fmt.Errorf("%q is not a hostname", hostname)
	}
	if have, ok := Lookup(text, hostname); ok {
		return "", fmt.Errorf("%s already answers with %s", hostname, have)
	}
	line := fmt.Sprintf("%-20s %s", ip, hostname)
	out := strings.TrimRight(text, "\n")
	if out == "" {
		return line + "\n", nil
	}
	return out + "\n" + line + "\n", nil
}

// Remove deletes a hostname. A line that carried several names keeps the
// rest; a line left with no names goes away entirely.
func Remove(text, hostname string) (string, bool) {
	removed := false
	var lines []string
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		fields := strings.Fields(line)
		// A comment is not a record — the same guard Parse uses. Without it a
		// hostname that appears as a word inside a `#`-comment would be treated
		// as removable and the comment rewritten or dropped.
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			lines = append(lines, line)
			continue
		}
		var keep []string
		for _, h := range fields[1:] {
			if h == hostname {
				removed = true
				continue
			}
			keep = append(keep, h)
		}
		if len(keep) == len(fields)-1 {
			lines = append(lines, line) // untouched, byte for byte
			continue
		}
		if len(keep) > 0 {
			lines = append(lines, fmt.Sprintf("%-20s %s", fields[0], strings.Join(keep, " ")))
		}
	}
	if !removed {
		return text, false
	}
	out := strings.Join(lines, "\n")
	if out != "" {
		out += "\n"
	}
	return out, true
}

// ZoneBindings reads which hosts file serves which zone out of the Corefile.
//
// The binding is the Corefile's to declare — `sre.local` is served from
// `sre.hosts` because a server block says so, not because the names rhyme —
// so inferring a record's zone from anything but this parse would be a guess
// that breaks the day someone adds a zone.
func ZoneBindings(corefile string) map[string]string {
	out := map[string]string{}
	zone := ""
	for _, line := range strings.Split(corefile, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasSuffix(t, "{") {
			head := strings.TrimSpace(strings.TrimSuffix(t, "{"))
			if z, ok := strings.CutSuffix(head, ":53"); ok {
				zone = z
				continue
			}
			if strings.HasPrefix(head, "hosts ") && zone != "" {
				parts := strings.Fields(head)
				if len(parts) >= 2 {
					if i := strings.LastIndex(parts[1], "/"); i >= 0 {
						out[zone] = parts[1][i+1:]
					}
				}
			}
		}
	}
	return out
}

// ZoneKeyFor picks the hosts file a hostname belongs in: the longest zone
// suffix that matches, and the catch-all zone (".") when none does.
func ZoneKeyFor(hostname string, bindings map[string]string) (zone, key string) {
	best := ""
	for z := range bindings {
		if z == "." {
			continue
		}
		if (hostname == z || strings.HasSuffix(hostname, "."+z)) && len(z) > len(best) {
			best = z
		}
	}
	if best != "" {
		return best, bindings[best]
	}
	return ".", bindings["."]
}

// canonicalKeyOrder is the order `make sync` writes the ConfigMap keys in.
// Byte-compatibility with the Makefile is the requirement; anything the
// Makefile does not know about goes after, sorted.
var canonicalKeyOrder = []string{"innogrid.hosts", "sre.hosts", "misc.hosts"}

// OrderedKeys returns the zone keys present in data, in the order the repo
// file (and this renderer) writes them: the Makefile's canonical trio first,
// then anything else sorted. It is the single source of truth for that order,
// so a caller that needs the key sequence reads it here rather than parsing it
// back out of rendered YAML.
func OrderedKeys(data map[string]string) []string {
	keys := make([]string, 0, len(data))
	for _, k := range canonicalKeyOrder {
		if _, ok := data[k]; ok {
			keys = append(keys, k)
		}
	}
	var extra []string
	for k := range data {
		if !slices.Contains(canonicalKeyOrder, k) {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	return append(keys, extra...)
}

// ParseConfigMapYAML is the inverse of RenderConfigMapYAML: it recovers the
// zone→content map from the repo file's text. It exists because the IaC repo
// is the source of truth for a write — the edit is applied to what git holds,
// not to a possibly-newer live ConfigMap — so the write path has to read the
// repo file back into the same shape RenderConfigMapYAML emits.
//
// It parses only the shape this package writes: a `data:` block of `  <key>: |`
// entries whose content lines are indented four spaces. Round-trip identity
// (Render∘Parse and Parse∘Render on Render's own output) is asserted by test;
// blank lines between blocks are the separators Render writes and are dropped,
// which is lossless for hosts-file content (a blank line is not a record).
func ParseConfigMapYAML(y string) map[string]string {
	out := map[string]string{}
	inData := false
	key := ""
	var buf []string
	flush := func() {
		if key == "" {
			return
		}
		if len(buf) == 0 {
			out[key] = ""
			return
		}
		out[key] = strings.Join(buf, "\n") + "\n"
	}
	for _, line := range strings.Split(y, "\n") {
		if !inData {
			if strings.TrimRight(line, " ") == "data:" {
				inData = true
			}
			continue
		}
		// A `  <key>: |` line opens a new block.
		if k, ok := blockKey(line); ok {
			flush()
			key, buf = k, nil
			continue
		}
		if content, ok := strings.CutPrefix(line, "    "); ok {
			buf = append(buf, content)
		}
		// Anything else (a blank separator, or trailing document lines) is not
		// content and is skipped — the block ends at the next key or EOF.
	}
	flush()
	return out
}

// blockKey matches a `  <key>: |` line and returns the key.
func blockKey(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "  ")
	if !ok || strings.HasPrefix(rest, " ") {
		return "", false // deeper indent is content, not a key
	}
	name, ok := strings.CutSuffix(rest, ": |")
	if !ok || name == "" || strings.ContainsAny(name, " \t") {
		return "", false
	}
	return name, true
}

// RenderConfigMapYAML reproduces the repo's configmap-hosts.yaml exactly as
// the Makefile's `make sync` writes it, from the live data. One renderer for
// both writers means a vctl commit and a hand sync can never fight over
// formatting.
func RenderConfigMapYAML(data map[string]string) string {
	var b strings.Builder
	b.WriteString(`# ============================================================
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
`)
	for i, k := range OrderedKeys(data) {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "  %s: |\n", k)
		for _, line := range strings.Split(strings.TrimRight(data[k], "\n"), "\n") {
			if line == "" {
				b.WriteString("\n")
				continue
			}
			b.WriteString("    ")
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
