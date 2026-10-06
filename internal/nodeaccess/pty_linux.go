//go:build linux

package nodeaccess

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func runLocalPTY(ctx context.Context, columns, rows int, input <-chan ShellMessage, output *shellWriter) (int, error) {
	shellCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	masterFD, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open PTY master: %w", err)
	}
	master := os.NewFile(uintptr(masterFD), "vctl-pty-master")
	defer master.Close()
	if err := unix.IoctlSetPointerInt(masterFD, unix.TIOCSPTLCK, 0); err != nil {
		return -1, fmt.Errorf("unlock PTY: %w", err)
	}
	ptyNumber, err := unix.IoctlGetInt(masterFD, unix.TIOCGPTN)
	if err != nil {
		return -1, fmt.Errorf("read PTY number: %w", err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", ptyNumber), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return -1, fmt.Errorf("open PTY slave: %w", err)
	}
	defer slave.Close()
	if columns < 1 || columns > 500 {
		columns = 80
	}
	if rows < 1 || rows > 500 {
		rows = 24
	}
	if err := unix.IoctlSetWinsize(masterFD, unix.TIOCSWINSZ, &unix.Winsize{Col: uint16(columns), Row: uint16(rows)}); err != nil {
		return -1, fmt.Errorf("set initial terminal size: %w", err)
	}
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, "-l")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start login shell: %w", err)
	}
	processDone := make(chan struct{})
	go func() {
		select {
		case <-shellCtx.Done():
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGHUP)
			timer := time.NewTimer(3 * time.Second)
			defer timer.Stop()
			select {
			case <-processDone:
			case <-timer.C:
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		case <-processDone:
		}
	}()
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 16<<10)
		for {
			n, readErr := master.Read(buffer)
			if n > 0 {
				if _, writeErr := output.Write(buffer[:n]); writeErr != nil {
					readDone <- writeErr
					return
				}
			}
			if readErr != nil {
				readDone <- readErr
				return
			}
		}
	}()
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		for {
			select {
			case <-shellCtx.Done():
				return
			case message := <-input:
				switch message.Type {
				case "input":
					if len(message.Data) > 0 {
						_, _ = master.Write(message.Data)
					}
				case "resize":
					if message.Columns > 0 && message.Columns <= 500 && message.Rows > 0 && message.Rows <= 500 {
						_ = unix.IoctlSetWinsize(masterFD, unix.TIOCSWINSZ, &unix.Winsize{Col: message.Columns, Row: message.Rows})
					}
				case "close":
					cancel()
					return
				}
			}
		}
	}()
	waitErr := cmd.Wait()
	close(processDone)
	cancel()
	_ = master.Close()
	<-inputDone
	select {
	case <-readDone:
	case <-time.After(time.Second):
	}
	if waitErr == nil {
		return 0, nil
	}
	if exit, ok := waitErr.(*exec.ExitError); ok {
		return exit.ExitCode(), nil
	}
	if ctx.Err() != nil {
		return -1, ctx.Err()
	}
	return -1, fmt.Errorf("wait for login shell: %w", waitErr)
}
