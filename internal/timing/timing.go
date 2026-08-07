// Package timing measures where a command's wall clock actually goes.
//
// It exists because the obvious answer was wrong. A listing that takes half a
// second looks like a slow query, and the fix that suggests itself is a better
// index or fewer rows — measured here, the query is tens of milliseconds and
// the rest is authenticating to Vault, minting a database credential and
// completing a TLS handshake. Optimising the part that was already fast is the
// default outcome of not measuring.
//
// Off unless asked for, and it costs one boolean check when off. On, it prints
// one block to stderr as the command exits, so it never interleaves with the
// output somebody is reading.
package timing

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// One recorder per process. A command is one process and one run, and threading
// a collector through every layer — app, store, renderers — to measure a debug
// flag would change the shape of code that has nothing to do with timing.
var (
	mu      sync.Mutex
	on      bool
	spans   []span
	started time.Time
)

type span struct {
	name  string
	took  time.Duration
	count int
}

// Enable turns measurement on and starts the clock for total elapsed.
func Enable() {
	mu.Lock()
	defer mu.Unlock()
	on = true
	started = time.Now()
	spans = nil
}

// Enabled reports whether anything is being measured.
func Enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return on
}

// Start opens a span and returns the function that closes it.
//
//	defer timing.Start("vault-login")()
//
// Spans with the same name accumulate, so a phase that runs per connection
// reports its total and how many times it happened — which is the fact that
// matters for a pool that opens several.
func Start(name string) func() {
	if !Enabled() {
		return func() {}
	}
	at := time.Now()
	return func() { record(name, time.Since(at)) }
}

// Record adds a duration measured by the caller, for a phase whose clock cannot
// be a simple defer — one nested inside another, where the outer has to
// subtract the inner to stay honest.
func Record(name string, d time.Duration) {
	if !Enabled() || d <= 0 {
		return
	}
	record(name, d)
}

func record(name string, d time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	for i := range spans {
		if spans[i].name == name {
			spans[i].took += d
			spans[i].count++
			return
		}
	}
	spans = append(spans, span{name: name, took: d, count: 1})
}

// Report writes what was measured, longest first, with the share of total each
// phase took. Nothing is printed when measurement is off or nothing ran.
func Report(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	if !on || len(spans) == 0 {
		return
	}
	total := time.Since(started)
	ordered := make([]span, len(spans))
	copy(ordered, spans)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].took > ordered[j].took })

	fmt.Fprintf(w, "\ntiming · total %s\n", round(total))
	for _, s := range ordered {
		share := ""
		if total > 0 {
			share = fmt.Sprintf("  %4.1f%%", float64(s.took)/float64(total)*100)
		}
		times := ""
		if s.count > 1 {
			times = fmt.Sprintf("  ×%d", s.count)
		}
		fmt.Fprintf(w, "  %-22s %8s%s%s\n", s.name, round(s.took), share, times)
	}
	// What is left is everything nobody instrumented — process start, flag
	// parsing, and whatever else. Naming it stops the measured phases from
	// looking like the whole story.
	var measured time.Duration
	for _, s := range ordered {
		measured += s.took
	}
	if rest := total - measured; rest > 0 {
		fmt.Fprintf(w, "  %-22s %8s  %4.1f%%\n", "(unmeasured)", round(rest), float64(rest)/float64(total)*100)
	}
}

// round keeps the numbers readable: milliseconds are what these phases are
// measured in, and nine digits of nanoseconds hide that.
func round(d time.Duration) string {
	switch {
	case d >= time.Second:
		return d.Round(10 * time.Millisecond).String()
	case d >= time.Millisecond:
		return d.Round(100 * time.Microsecond).String()
	default:
		return d.Round(time.Microsecond).String()
	}
}
