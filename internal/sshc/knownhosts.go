package sshc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyCallback 은 ~/.ssh/known_hosts 로 호스트 키를 검증하되,
// 처음 보는 호스트는 TOFU(trust-on-first-use)로 등록한다.
// 이미 등록된 키와 다르면(중간자 의심) 거부한다.
func hostKeyCallback() ssh.HostKeyCallback {
	home, err := os.UserHomeDir()
	if err != nil {
		return rejectHostKey(fmt.Errorf("home directory lookup: %w", err))
	}
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	_ = os.MkdirAll(filepath.Dir(khPath), 0o700)
	if f, err := os.OpenFile(khPath, os.O_CREATE|os.O_APPEND, 0o600); err == nil {
		f.Close()
	}

	verify, err := knownhosts.New(khPath)
	if err != nil {
		return rejectHostKey(fmt.Errorf("known_hosts load %s: %w", khPath, err))
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verify(hostname, remote, key)
		if err == nil {
			return nil
		}
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			// 처음 보는 호스트 → 등록(TOFU)
			return appendKnownHost(khPath, hostname, remote, key)
		}
		// 등록된 키와 불일치 등 → 그대로 거부
		return err
	}
}

func rejectHostKey(reason error) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return fmt.Errorf("host key verification unavailable for %s: %w", hostname, reason)
	}
}

func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	addrs := []string{knownhosts.Normalize(hostname)}
	if remote != nil {
		if n := knownhosts.Normalize(remote.String()); n != addrs[0] {
			addrs = append(addrs, n)
		}
	}
	line := knownhosts.Line(addrs, key)
	if _, err := fmt.Fprintln(f, line); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "known_hosts 에 새 호스트 키 등록: %s\n", hostname)
	return nil
}
