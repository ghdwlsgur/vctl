package socks5

import (
	"net"
	"sync"
	"time"
)

// Tracker counts the clients a server has open and remembers when the last
// one left, so a tunnel nobody is using can notice and shut itself down. The
// zero value is ready; a nil *Tracker is accepted everywhere and counts
// nothing.
type Tracker struct {
	mu   sync.Mutex
	open int
	seen bool      // a client has connected at least once
	last time.Time // when the count last fell to zero
}

func (t *Tracker) begin() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.open++
	t.seen = true
	t.mu.Unlock()
}

func (t *Tracker) end() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.open--
	if t.open == 0 {
		t.last = time.Now()
	}
	t.mu.Unlock()
}

// Open is how many clients are connected right now.
func (t *Tracker) Open() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.open
}

// IdleSince reports how long the server has had no client: since the last one
// left, or since `since` if none ever connected. ok is false while a client is
// connected.
func (t *Tracker) IdleSince(since, now time.Time) (idle time.Duration, ok bool) {
	if t == nil {
		return now.Sub(since), true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.open > 0 {
		return 0, false
	}
	from := since
	if t.seen && t.last.After(from) {
		from = t.last
	}
	return now.Sub(from), true
}

func (t *Tracker) wrap(serve func(net.Conn)) func(net.Conn) {
	if t == nil {
		return serve
	}
	return func(c net.Conn) {
		t.begin()
		defer t.end()
		serve(c)
	}
}
