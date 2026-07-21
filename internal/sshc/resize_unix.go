//go:build !windows

package sshc

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func watchResize(sess *ssh.Session, fd int) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	defer signal.Stop(ch)
	for range ch {
		if w, h, err := term.GetSize(fd); err == nil {
			_ = sess.WindowChange(h, w)
		}
	}
}
