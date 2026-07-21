//go:build windows

package cli

// watch-sessions is a Linux host-daemon feature; keeping these best-effort
// helpers inert lets the Windows management CLI build without pretending that
// Windows has Linux process/cgroup semantics.
func processAlive(_ int) bool { return false }
func cgroupID(_ int) int64    { return 0 }
