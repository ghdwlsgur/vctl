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

// hostKeyCallback verifies host keys with ~/.ssh/known_hosts.
// Unknown hosts are recorded with TOFU. Mismatched known keys are rejected.
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
			// Unknown host. Record it through TOFU.
			return appendKnownHost(khPath, hostname, remote, key)
		}
		// Known-host mismatch or parser errors are rejected.
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
	fmt.Fprintf(os.Stderr, "added new host key to known_hosts: %s\n", hostname)
	return nil
}
