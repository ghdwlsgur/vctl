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
	if _, err := netip.ParseAddr(ip); err != nil {
		return "", fmt.Errorf("%q is not an IP address", ip)
	}
	if hostname == "" || strings.ContainsAny(hostname, " \t\n#") {
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
		if len(fields) < 2 {
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
	keys = append(keys, extra...)

	for i, k := range keys {
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
