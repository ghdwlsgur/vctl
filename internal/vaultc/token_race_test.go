package vaultc

import (
	"sync"
	"testing"
)

// pgxpool's credential callback reads token state from whatever goroutine
// opens a connection, while a login, renewal, or logout on another writes it.
// tokenExp and renewable are this client's own fields, so this client owns the
// lock — the test is only meaningful under -race, where an unguarded field
// fails it.
func TestTokenStateIsSafeUnderConcurrentReadsAndWrites(t *testing.T) {
	c, err := New("https://127.0.0.1:8200", nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				c.HasValidToken()
				c.TTL()
				c.Renewable()
				c.Expiry()
			}
		})
	}
	// Logout is the exported path that writes both guarded fields.
	for range 4 {
		wg.Go(func() {
			for range 200 {
				_ = c.Logout()
			}
		})
	}
	wg.Wait()
}
