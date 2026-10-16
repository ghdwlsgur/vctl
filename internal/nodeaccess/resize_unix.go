//go:build !windows

package nodeaccess

import (
	"os"
	"syscall"
)

// resizeSignals is what tells the client the local terminal changed size.
func resizeSignals() []os.Signal { return []os.Signal{syscall.SIGWINCH} }
