//go:build !windows

package cli

import (
	"syscall"
)

// detachAttr puts the child in its own session, so the terminal that started
// it — or the kubectl that started the vctl that started it — can end
// without taking the tunnel with it.
func detachAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }

func terminateProcess(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
