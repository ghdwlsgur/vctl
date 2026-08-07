package cli

import (
	"context"
	"math/rand/v2"
	"time"
)

// runWatchLoop runs a dependency-backed watcher without hammering Vault or the
// database during an outage. Consecutive failures exponentially increase the
// delay up to maxBackoff; one successful scan resets it to interval.
//
// wait is injectable so the retry schedule can be tested without wall-clock
// sleeps. It returns false when the loop should stop (normally ctx cancellation).
func runWatchLoop(
	ctx context.Context,
	interval time.Duration,
	maxBackoff time.Duration,
	fn func() error,
	onErr func(error),
	wait func(context.Context, time.Duration) bool,
) error {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if maxBackoff < interval {
		maxBackoff = interval
	}

	retryDelay := interval
	for {
		delay := interval
		if err := fn(); err != nil {
			if onErr != nil {
				onErr(err)
			}
			delay = retryDelay
			retryDelay = min(retryDelay*2, maxBackoff)
		} else {
			retryDelay = interval
		}
		if !wait(ctx, delay) {
			return nil
		}
	}
}

func waitForContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// jitterWatchDelay spreads a fleet-wide dependency recovery over a ±20%
// window instead of making every host retry Vault/Postgres on the same tick.
func jitterWatchDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return delay
	}
	span := delay / 5
	if span <= 0 {
		return delay
	}
	return delay - span + time.Duration(rand.Int64N(int64(2*span)+1))
}
