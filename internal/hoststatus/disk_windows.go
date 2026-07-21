//go:build windows

package hoststatus

import "golang.org/x/sys/windows"

func diskUsedPct(path string) *float64 {
	root, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	var available, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(root, &available, &total, &free); err != nil || total == 0 {
		return nil
	}
	used := float64(total-free) / float64(total) * 100
	return &used
}
