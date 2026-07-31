// Package dbcreds keeps one Vault database credential alive across many
// connections instead of issuing a new one for each.
//
// The pool in internal/store recycles physical connections on a timer so a
// connection never outlives its credential's lease. Before this package, every
// recycle also issued a new credential, which is the expensive half: Vault runs
// a CREATE ROLE against Postgres and schedules a DROP ROLE for expiry. Measured
// on the fleet, 42 status agents produced 114 dynamic roles per hour to write
// one row each every five minutes.
//
// Renewing decouples the two. Connections still recycle on their own schedule,
// but they hand back the same cached credential, and a renewal moves that
// credential's expiry without touching Postgres at all. A new role is created
// only when the lease reaches the max_ttl Vault will not extend past.
package dbcreds

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

// Issuer is the slice of the Vault client this package needs. Keeping it this
// narrow is what makes the expiry arithmetic testable without a Vault server;
// the failure modes here are all about clocks, and a real server would only
// make them harder to provoke.
type Issuer interface {
	Issue(ctx context.Context) (vaultc.DBLease, error)
	Renew(ctx context.Context, leaseID string, increment time.Duration) (ttl time.Duration, renewable bool, err error)
}

// Cache hands out one credential for as long as Vault will keep it alive.
//
// It is safe for concurrent use: the pool opens connections from several
// goroutines, and without the lock they would each see an empty cache and issue
// a credential apiece, which is the exact cost this package exists to avoid.
type Cache struct {
	iss Issuer

	// minRemaining is the floor on how much lease a returned credential must
	// still have. It exists because the caller is not asking "is this valid
	// now" but "may I open a connection that will live for a while". The value
	// must exceed the pool's maximum connection age; see store.MaxConnAge.
	minRemaining time.Duration

	// renewFor is how much extension to ask for. Vault clamps it to what
	// remains of max_ttl, so asking for more than it will grant is harmless.
	renewFor time.Duration

	now func() time.Time

	mu      sync.Mutex
	lease   vaultc.DBLease
	expires time.Time
}

// New returns a Cache that keeps a credential usable for at least minRemaining.
//
// minRemaining should be derived from the consumer's connection lifetime rather
// than picked: a credential with less than a connection's maximum age left will
// be revoked underneath a connection that is still in the pool.
func New(iss Issuer, minRemaining, renewFor time.Duration) *Cache {
	return &Cache{iss: iss, minRemaining: minRemaining, renewFor: renewFor, now: time.Now}
}

// Get returns credentials guaranteed to outlive minRemaining.
//
// The order matters. Renewal is tried before re-issuing because it is the cheap
// path, but its result is checked rather than assumed: Vault clamps a renewal
// to what is left of max_ttl, so near that ceiling a renewal "succeeds" and
// still leaves the credential expiring too soon. That case has to fall through
// to a fresh issue, or the caller gets a credential that dies mid-connection.
func (c *Cache) Get(ctx context.Context) (user, pass string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.usable() {
		return c.lease.User, c.lease.Pass, nil
	}
	if c.lease.ID != "" && c.lease.Renewable {
		if err := c.renew(ctx); err == nil && c.usable() {
			return c.lease.User, c.lease.Pass, nil
		}
		// A renewal that failed or did not buy enough time is not an error yet;
		// issuing a new credential still satisfies the caller. Falling through
		// also covers the lease having been revoked out from under us.
	}
	if err := c.issue(ctx); err != nil {
		return "", "", err
	}
	return c.lease.User, c.lease.Pass, nil
}

// usable reports whether the cached credential still has minRemaining left.
func (c *Cache) usable() bool {
	return c.lease.User != "" && c.expires.Sub(c.now()) >= c.minRemaining
}

func (c *Cache) issue(ctx context.Context) error {
	l, err := c.iss.Issue(ctx)
	if err != nil {
		return fmt.Errorf("issue db credential: %w", err)
	}
	// A fresh credential that already fails the floor means the role's TTL is
	// configured below what the connection pool needs. Reporting it here names
	// the real problem; the alternative is connections dying on a cadence
	// nobody can trace back to a Vault role definition.
	c.lease, c.expires = l, c.now().Add(l.TTL)
	if !c.usable() {
		return fmt.Errorf("db credential TTL %v is shorter than the %v a connection may live: raise the Vault role's default_ttl", l.TTL, c.minRemaining)
	}
	return nil
}

func (c *Cache) renew(ctx context.Context) error {
	ttl, renewable, err := c.iss.Renew(ctx, c.lease.ID, c.renewFor)
	if err != nil {
		// Drop the lease rather than keep retrying a handle Vault has already
		// rejected; the caller falls through to issuing a new one.
		c.lease, c.expires = vaultc.DBLease{}, time.Time{}
		return err
	}
	c.lease.Renewable = renewable
	c.expires = c.now().Add(ttl)
	return nil
}
