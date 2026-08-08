package cli

import (
	"context"
	"errors"
	"sync"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/store"
)

// openLater is the inventory store, opened the first time something actually
// needs it and kept until the command is done.
//
// Wrapping a command in withStore opens the store before deciding whether it is
// needed, and that decision is most of the cost: measured against this fleet, a
// listing spends 55% of its time minting a database credential and 43%
// completing a TLS handshake, against 2% on the query. The OpenStack listings
// can answer from a stored reading, and the ones that can should not pay for a
// connection to find that out.
//
// One connection rather than one per read: the setup is the expensive part, so
// a browser refreshing three times should pay it once.
type openLater struct {
	app *app.App

	mu     sync.Mutex
	st     *store.Store
	closed bool
}

// errStoreClosed is what a read still in flight gets when the command it
// belonged to has already returned. Nothing is left to show it, which is the
// point: it is not a failure, it is a read nobody is waiting for any more.
var errStoreClosed = errors.New("the store has closed")

// use runs fn with the store.
//
// The lock is held for the whole call rather than only the open, so Close
// cannot take the pool out from under a read that is still running — the
// browser's refresh runs in its own goroutine and the program can return while
// one is in flight.
func (l *openLater) use(ctx context.Context, fn func(*store.Store) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errStoreClosed
	}
	if l.st == nil {
		st, err := l.app.OpenStore(ctx, app.PurposeInventoryRead)
		if err != nil {
			return err
		}
		l.st = st
	}
	return fn(l.st)
}

// Close releases the connection, waiting for any read still using it.
func (l *openLater) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	if l.st != nil {
		l.st.Close()
		l.st = nil
	}
}
