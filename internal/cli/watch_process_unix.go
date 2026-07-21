//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	return err == nil && p.Signal(syscall.Signal(0)) == nil
}

// cgroupID resolves a pid's cgroup v2 kernfs inode, matching Tetragon.
func cgroupID(pid int) int64 {
	if pid <= 0 {
		return 0
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return 0
	}
	line := strings.TrimSpace(string(b))
	idx := strings.LastIndex(line, "::")
	if idx < 0 {
		return 0
	}
	rel := strings.TrimPrefix(line[idx+2:], "/")
	fi, err := os.Stat(filepath.Join("/sys/fs/cgroup", rel))
	if err != nil {
		return 0
	}
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int64(stat.Ino)
	}
	return 0
}
