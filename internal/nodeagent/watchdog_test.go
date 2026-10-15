package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// listen stands in for systemd: a datagram socket plus the environment it sets
// on the service it is watching.
func listen(t *testing.T, usec, pid string) *net.UnixConn {
	t.Helper()
	// Not t.TempDir(). A unix socket address is capped near 104 bytes on darwin
	// and t.TempDir() spells the test's name into the path, so the longer names
	// here bind-failed and the tests skipped themselves — measured. A skipped
	// test reads the same as a passing one.
	dir, err := os.MkdirTemp("", "wd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "n")
	c, err2 := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: sock, Net: "unixgram"})
	if err2 != nil {
		t.Fatalf("unixgram listen: %v", err2)
	}
	t.Cleanup(func() { c.Close() })
	t.Setenv("NOTIFY_SOCKET", sock)
	t.Setenv("WATCHDOG_USEC", usec)
	if pid != "" {
		t.Setenv("WATCHDOG_PID", pid)
	}
	return c
}

// The ping systemd is waiting for actually arrives.
func TestWatchdogPingsSystemd(t *testing.T) {
	srv := listen(t, "30000000", "") // 30s

	w := newWatchdog()
	if w == nil {
		t.Fatal("no watchdog built from a complete environment")
	}
	defer w.close()
	if got := w.Interval(); got != 30*time.Second {
		t.Errorf("interval = %s, want 30s", got)
	}

	w.ping(nil)
	buf := make([]byte, 64)
	srv.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatalf("nothing arrived: %v", err)
	}
	if got := string(buf[:n]); got != "WATCHDOG=1" {
		t.Errorf("payload = %q, want WATCHDOG=1", got)
	}
}

// Outside systemd the whole thing is inert, so the same binary runs unchanged on
// a laptop and on a host whose unit predates this.
func TestWatchdogIsInertWithoutSystemd(t *testing.T) {
	for _, tc := range []struct{ name, usec, sock string }{
		{"no WATCHDOG_USEC", "", "/tmp/x"},
		{"zero WATCHDOG_USEC", "0", "/tmp/x"},
		{"unparseable", "soon", "/tmp/x"},
		{"no NOTIFY_SOCKET", "30000000", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WATCHDOG_USEC", tc.usec)
			t.Setenv("NOTIFY_SOCKET", tc.sock)
			w := newWatchdog()
			if w != nil {
				t.Fatalf("built a watchdog from %+v", tc)
			}
			// The nil receiver has to be safe: every call site holds one.
			w.ping(func(string, ...any) { t.Error("a nil watchdog warned") })
			w.close()
			if got := w.Interval(); got != 0 {
				t.Errorf("interval = %s, want 0", got)
			}
		})
	}
}

// A child that inherited the environment must not answer for its parent.
//
// The point of the watchdog is that a wedged main process stops being able to
// say it is alive. A forked probe holding the same NOTIFY_SOCKET would keep the
// unit looking healthy and hide exactly that.
func TestWatchdogRefusesToAnswerForAnotherProcess(t *testing.T) {
	listen(t, "30000000", "1") // pid 1 is not this test
	if w := newWatchdog(); w != nil {
		w.close()
		t.Fatal("answered on behalf of another pid")
	}
}

// An interval at or past WatchdogSec turns a working agent into a restart loop.
// The unit and the flag live in different files, so this says so out loud.
func TestWatchdogWarnsWhenTheIntervalOutrunsIt(t *testing.T) {
	listen(t, "300000000", "") // 300s
	w := newWatchdog()
	if w == nil {
		t.Fatal("no watchdog")
	}
	defer w.close()

	for _, tc := range []struct {
		name     string
		interval time.Duration
		want     bool
	}{
		{"comfortably inside", 60 * time.Second, false},
		{"exactly equal", 300 * time.Second, true},
		{"past it", 10 * time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var msg string
			warnTooSlow(w, tc.interval, func(f string, a ...any) { msg = f })
			if got := msg != ""; got != tc.want {
				t.Errorf("warned = %v, want %v (msg %q)", got, tc.want, msg)
			}
			if tc.want && !strings.Contains(msg, "WatchdogSec") {
				t.Errorf("warning does not name WatchdogSec: %q", msg)
			}
		})
	}
}

// A socket that stops accepting must not take the agent down with it, and must
// not fill the journal either.
func TestWatchdogSurvivesADeadSocketAndWarnsOnce(t *testing.T) {
	srv := listen(t, "30000000", "")
	w := newWatchdog()
	if w == nil {
		t.Fatal("no watchdog")
	}
	defer w.close()
	srv.Close()

	n := 0
	for range 5 {
		w.ping(func(string, ...any) { n++ })
	}
	if n > 1 {
		t.Errorf("warned %d times, want at most 1", n)
	}
}

// A failed report is still the loop going round, until the failures have gone
// on long enough that a restart is the cheaper explanation to test. A Vault or
// Postgres blink must not restart the agent; a process that has failed every
// report for an hour is worth starting fresh.
func TestFailureStreakWithholdsThePingOnlyAfterAnHourOfFailures(t *testing.T) {
	var s failureStreak
	t0 := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	failed := errors.New("postgres ping: context deadline exceeded")

	for _, at := range []time.Duration{0, 5 * time.Minute, 59 * time.Minute} {
		if ping, _ := s.observe(failed, t0.Add(at)); !ping {
			t.Fatalf("failing for %s withheld the ping; a short outage must not restart the agent", at)
		}
	}
	ping, first := s.observe(failed, t0.Add(time.Hour))
	if ping || !first {
		t.Fatalf("after an hour of failures: ping=%v first=%v, want the ping withheld and the transition reported", ping, first)
	}
	if ping, first := s.observe(failed, t0.Add(65*time.Minute)); ping || first {
		t.Errorf("still failing: ping=%v first=%v, want it withheld and reported only once", ping, first)
	}
}

// One success ends the streak, so the next outage gets its full hour again.
func TestFailureStreakResetsOnSuccess(t *testing.T) {
	var s failureStreak
	t0 := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	failed := errors.New("write failed")

	s.observe(failed, t0)
	s.observe(failed, t0.Add(time.Hour)) // withheld
	if ping, _ := s.observe(nil, t0.Add(61*time.Minute)); !ping {
		t.Fatal("a successful report withheld the ping")
	}
	if ping, _ := s.observe(failed, t0.Add(62*time.Minute)); !ping {
		t.Error("the first failure after a success was treated as part of the old streak")
	}
}

// The loop itself stops answering systemd once reports have failed for an
// hour. This is the 2026-10-15 failure: two agents stuck over their cgroup
// MemoryHigh failed every report for two days, still went round, still pinged,
// and systemd never restarted them.
func TestTheHeartbeatStopsPingingAfterAnHourOfFailedReports(t *testing.T) {
	srv := listen(t, "1200000000", "") // 20m

	t0 := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	ticks := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var warnings []string
	a := &Agent{
		Hostname: "host-01", Version: "test", Interval: time.Millisecond,
		OpenSink: func(context.Context) (Sink, error) { return &fakeStatusSink{err: errors.New("write failed")}, nil },
		Warnf: func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			warnings = append(warnings, fmt.Sprintf(format, args...))
		},
		Infof: func(string, ...any) {},
		// Twenty minutes a report: the first three fall inside the hour.
		now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			at := t0.Add(time.Duration(ticks) * 20 * time.Minute)
			ticks++
			if ticks > 6 {
				cancel()
			}
			return at
		},
	}
	done := make(chan error, 1)
	go func() { done <- a.heartbeatLoop(ctx, &conn{open: a.OpenSink, log: a}) }()
	if err := <-done; err != nil {
		t.Fatalf("heartbeat loop: %v", err)
	}

	pings := 0
	buf := make([]byte, 64)
	for {
		srv.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := srv.Read(buf); err != nil {
			break
		}
		pings++
	}
	if pings != 3 {
		t.Errorf("systemd got %d pings, want 3 (reports at 0, 20 and 40 minutes) and none after the hour", pings)
	}
	mu.Lock()
	defer mu.Unlock()
	withheld := 0
	for _, w := range warnings {
		if strings.Contains(w, "withholding the systemd watchdog") {
			withheld++
		}
	}
	if withheld != 1 {
		t.Errorf("the withheld ping was announced %d times, want once: %q", withheld, warnings)
	}
}
