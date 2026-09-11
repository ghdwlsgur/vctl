//go:build windows

package cli

import "syscall"

// processAlive asks the kernel whether pid is still running. Shared by the
// tunnel state file (`vctl wg status` / on-demand start) and the Linux-only
// watch-sessions helpers, which stay inert here.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// cgroupID is a Linux cgroup v2 lookup; Windows has no equivalent.
func cgroupID(_ int) int64 { return 0 }
