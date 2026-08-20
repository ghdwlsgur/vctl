//go:build !windows

package hoststatus

import (
	"bytes"
	"io"
	"os"
)

// mountCountCap bounds the read of /proc/self/mountinfo.
//
// The file is procfs, so it reports size 0 and has to be read to be measured.
// On a healthy host it is about 35KB; the host that prompted this had 2.8MB
// after a container runtime leaked 16,383 mounts. Reading a few megabytes once
// every five minutes is nothing — it was the endless re-reading that cost a
// core — but an unbounded read of a file that has no declared size is how a
// heartbeat becomes the expensive thing it is meant to watch for.
//
// 8MB is roughly 45,000 mounts, well past anything worth distinguishing: by then
// the answer is "far too many" and one more digit does not change what anybody
// does about it.
const mountCountCap = 8 << 20

// mountCount reports how many entries are in this process's mount table.
//
// A floor, not an exact count, when the table is larger than the cap. That is
// the honest shape for what this is used for — the alert fires on a threshold
// in the hundreds, so a floor above it is as actionable as an exact number.
//
// nil when the file cannot be read at all, which is every non-Linux host and any
// sandbox that hides procfs. Absent is not zero: a host with no measurement and
// a host with an empty mount table must not read the same.
func mountCount() *int {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()

	n := 0
	buf := make([]byte, 64<<10)
	read := 0
	for read < mountCountCap {
		c, err := f.Read(buf)
		if c > 0 {
			read += c
			n += bytes.Count(buf[:c], []byte{'\n'})
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			// Partial answer over none: a short read still says the table is at
			// least this large, and that is the direction the alert cares about.
			break
		}
	}
	return &n
}
