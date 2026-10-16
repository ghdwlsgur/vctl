//go:build windows

package nodeaccess

import "os"

// resizeSignals is empty on Windows, which has no SIGWINCH: the remote PTY
// keeps the size it started with.
func resizeSignals() []os.Signal { return nil }
