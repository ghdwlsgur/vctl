//go:build !windows

package hoststatus

import "syscall"

func diskUsedPct(path string) *float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return nil
	}
	used := float64(st.Blocks-st.Bavail) / float64(st.Blocks) * 100
	return &used
}
