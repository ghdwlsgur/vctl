//go:build windows

package sshc

import "golang.org/x/crypto/ssh"

// Windows has no SIGWINCH equivalent. The initial PTY size is still sent by
// shell; resizing an already-open interactive session is unsupported for now.
func watchResize(_ *ssh.Session, _ int) {}
