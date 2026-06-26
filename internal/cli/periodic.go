package cli

import (
	"context"
	"time"
)

// runPeriodic runs fn once, then on every interval tick until ctx is cancelled.
//
//   - once=true: run fn a single time and return its error.
//   - failFast=true: a first-run error aborts and is returned (tick errors still
//     go to onErr); failFast=false: the first-run error also goes to onErr and
//     the loop continues.
//   - onErr handles errors from ticks (and, when !failFast, the first run); nil
//     ignores them.
//   - interval<=0 falls back to defaultInterval (time.NewTicker panics on <=0).
//
// It collapses the once/interval-guard/NewTicker-select skeleton shared by the
// watch-sessions and node-agent daemons.
func runPeriodic(ctx context.Context, once, failFast bool, interval, defaultInterval time.Duration, fn func() error, onErr func(error)) error {
	if once {
		return fn()
	}
	if interval <= 0 {
		interval = defaultInterval
	}
	if err := fn(); err != nil {
		if failFast {
			return err
		}
		if onErr != nil {
			onErr(err)
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := fn(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}
