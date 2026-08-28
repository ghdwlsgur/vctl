package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"
)

// kvRedactor redacts filled-in values from a stream. It knows the exact bytes,
// so the filter is exact: each value, plus the base64 and URL-encoded forms a
// command is likely to print it in. Values shorter than kvMaskMin are not
// masked — a three-character "secret" would redact every "abc" on the screen,
// and it was never a secret.
//
// A safety net, not a guarantee: a value printed in hex, or split across two
// lines, passes. The guarantee is the shape of the command — the value never
// needs to be printed — and the mask is for the times a command prints it
// anyway.
type kvRedactor struct {
	mu      sync.Mutex
	needles []kvNeedle
	hits    map[string]int
}

type kvNeedle struct {
	bytes []byte
	key   string
}

const kvMaskMin = 4

func newKVRedactor(values map[string]string) *kvRedactor {
	m := &kvRedactor{hits: map[string]int{}}
	for key, v := range values {
		if len(v) < kvMaskMin {
			continue
		}
		seen := map[string]bool{}
		for _, form := range redactedForms(v) {
			if seen[form] {
				continue
			}
			seen[form] = true
			m.needles = append(m.needles, kvNeedle{[]byte(form), key})
		}
	}
	// Longest first, so a form that contains another is replaced whole.
	slices.SortStableFunc(m.needles, func(a, b kvNeedle) int { return len(b.bytes) - len(a.bytes) })
	return m
}

// redactedForms is every spelling of v the filter looks for: the value, its
// URL-encoding, and its base64 — also the base64 of the value with a newline
// on the end, because `echo "$X" | base64` is the commonest accident and echo
// appends one. Unless the value's length happens to be a multiple of three,
// that trailing byte changes the final base64 group, and a needle built from
// the bare value would miss the whole string.
func redactedForms(v string) []string {
	forms := []string{v, url.QueryEscape(v)}
	for _, raw := range []string{v, v + "\n"} {
		b := []byte(raw)
		forms = append(forms,
			base64.StdEncoding.EncodeToString(b),
			base64.RawStdEncoding.EncodeToString(b),
			base64.URLEncoding.EncodeToString(b),
			base64.RawURLEncoding.EncodeToString(b),
		)
	}
	return forms
}

// redact replaces every complete needle in buf and counts what it replaced.
func (m *kvRedactor) redact(buf []byte) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.needles {
		if c := bytes.Count(buf, n.bytes); c > 0 {
			m.hits[n.key] += c
			buf = bytes.ReplaceAll(buf, n.bytes, []byte("[REDACTED:"+n.key+"]"))
		}
	}
	return buf
}

// holdback is how many trailing bytes of buf could be the start of a needle
// whose rest has not arrived yet. Those wait for the next write; everything
// before them is safe to pass on.
func (m *kvRedactor) holdback(buf []byte) int {
	hold := 0
	for _, n := range m.needles {
		for l := min(len(n.bytes)-1, len(buf)); l > hold; l-- {
			if bytes.HasSuffix(buf, n.bytes[:l]) {
				hold = l
				break
			}
		}
	}
	return hold
}

func (m *kvRedactor) total() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.hits {
		n += c
	}
	return n
}

// report names what was masked, per field, in a stable order.
func (m *kvRedactor) report() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m.hits)) {
		parts = append(parts, fmt.Sprintf("%s ×%d", k, m.hits[k]))
	}
	return strings.Join(parts, ", ")
}

// maskWriter is one masked stream. stdout and stderr each get their own, over
// the same redactor, so the count covers both.
type maskWriter struct {
	m    *kvRedactor
	w    io.Writer
	tail []byte
}

func (m *kvRedactor) writer(w io.Writer) *maskWriter { return &maskWriter{m: m, w: w} }

// Write holds back first and redacts second. The order matters: one needle
// can be a proper prefix of another — base64 without its padding is the
// padded form minus "=" — and redacting the moment the short one is complete
// would print the long one's tail. So a suffix that could still grow into a
// longer needle waits, whole, for the next write, and only what cannot is
// redacted and released.
func (mw *maskWriter) Write(p []byte) (int, error) {
	buf := make([]byte, 0, len(mw.tail)+len(p))
	buf = append(append(buf, mw.tail...), p...)
	hold := mw.m.holdback(buf)
	if _, err := mw.w.Write(mw.m.redact(buf[:len(buf)-hold])); err != nil {
		return 0, err
	}
	mw.tail = append(mw.tail[:0], buf[len(buf)-hold:]...)
	return len(p), nil
}

// Flush redacts and releases what was held back. Called once the child has
// exited: there is no more output for a partial match to complete into, so
// whatever the tail is, it is final.
func (mw *maskWriter) Flush() error {
	if len(mw.tail) == 0 {
		return nil
	}
	_, err := mw.w.Write(mw.m.redact(mw.tail))
	mw.tail = nil
	return err
}
