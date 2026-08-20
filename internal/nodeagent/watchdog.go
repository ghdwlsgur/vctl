package nodeagent

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// The watchdog tells systemd the loop is still going round.
//
// It says nothing about whether the database is reachable. The heartbeat loop
// deliberately survives a failed report — an outage must not take the reporting
// down with it, and this unit turns off systemd's start rate limit for the same
// reason. Pinging only after a successful report would restart the agent every
// time Vault or Postgres blinked, which is the opposite of that.
//
// What it catches is the loop not going round at all. Measured on one host: a
// container runtime leaked 16,383 mounts, /proc/self/mountinfo reached 2.8MB,
// and something in the process re-read it forever. The agent stayed
// `active (running)`, pegged at its CPUQuota, and reported nothing for 57 days.
// systemd had no way to tell that from an idle agent — the process was there and
// had not exited. This gives it one.
//
// Absent WATCHDOG_USEC the whole thing is a no-op, so the same binary runs
// unchanged outside systemd and on hosts whose unit predates this.
type watchdog struct {
	conn     *net.UnixConn
	interval time.Duration
	failed   bool
}

// newWatchdog returns nil when systemd has not asked for keepalives.
//
// WATCHDOG_PID is checked because systemd sets these for the main process and a
// child inheriting the environment must not answer on its parent's behalf — a
// forked probe that outlived a wedged parent would keep the unit looking alive,
// which is the exact failure this is meant to expose.
func newWatchdog() *watchdog {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return nil
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return nil
	}
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	// An abstract socket is spelled with a leading @ in the environment and a
	// leading NUL on the wire.
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	c, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return nil
	}
	return &watchdog{conn: c, interval: time.Duration(usec) * time.Microsecond}
}

// Interval is what systemd will wait for. Callers ping well inside it.
func (w *watchdog) Interval() time.Duration {
	if w == nil {
		return 0
	}
	return w.interval
}

// ping is best effort and reports the first failure only.
//
// A send that fails is not a reason to stop working. The sandbox this unit runs
// under mounts /run/systemd read-only, and if that ever stops the socket from
// accepting a datagram the agent should keep reporting status rather than take
// itself down over its own liveness signal. The warning is emitted once so the
// condition is visible without filling the journal every cycle.
func (w *watchdog) ping(warnf func(string, ...any)) {
	if w == nil {
		return
	}
	if _, err := w.conn.Write([]byte("WATCHDOG=1")); err != nil {
		if !w.failed && warnf != nil {
			w.failed = true
			warnf("systemd watchdog ping failed, continuing without it: %v", err)
		}
		return
	}
	w.failed = false
}

func (w *watchdog) close() {
	if w != nil && w.conn != nil {
		_ = w.conn.Close()
	}
}

// warnTooSlow is the check that keeps the unit and the flag honest.
//
// systemd kills the service when a ping is late, so an interval longer than
// WatchdogSec turns a working agent into a restart loop. The unit ships with
// headroom, but --interval is a flag and the two are edited in different files
// by different people.
func warnTooSlow(w *watchdog, interval time.Duration, warnf func(string, ...any)) {
	if w == nil || warnf == nil {
		return
	}
	if interval >= w.Interval() {
		warnf("--interval %s is not shorter than WatchdogSec %s; systemd will restart this agent between reports. %s",
			interval, w.Interval(),
			fmt.Sprintf("Raise WatchdogSec above %s or lower --interval.", interval))
	}
}
