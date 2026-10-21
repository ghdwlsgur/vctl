//go:build !linux

package hwspec

// ethtoolPort has no equivalent off Linux; the collector then reports speed alone.
func ethtoolPort(string) (fibre, copper bool, maxMb int, ok bool) { return false, false, 0, false }
