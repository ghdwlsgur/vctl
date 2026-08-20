//go:build windows

package hoststatus

// Windows has no /proc/self/mountinfo. Absent rather than zero — see
// mounts_unix.go for why the difference matters.
func mountCount() *int { return nil }
