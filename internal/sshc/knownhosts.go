package sshc

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

// hostKeyCallback verifies host keys with ~/.ssh/known_hosts.
// Unknown hosts require an explicit terminal confirmation. Non-interactive
// callers reject them. Mismatched known keys are always rejected.
func hostKeyCallback(confirmUnknown bool) ssh.HostKeyCallback {
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
			if !confirmUnknown || !term.IsTerminal(int(os.Stdin.Fd())) {
				return fmt.Errorf("unknown SSH host key for %s (%s); connect interactively once to verify it", hostname, ssh.FingerprintSHA256(key))
			}
			if !confirmHostKey(hostname, key) {
				return fmt.Errorf("SSH host key for %s was not trusted", hostname)
			}
			return appendKnownHost(khPath, hostname, remote, key)
		}
		// Known-host mismatch or parser errors are rejected.
		return err
	}
}

func confirmHostKey(hostname string, key ssh.PublicKey) bool {
	fmt.Fprintf(os.Stderr, "The authenticity of %s is unknown.\nSHA256 fingerprint: %s\nTrust this host key? [y/N] ", hostname, ssh.FingerprintSHA256(key))
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
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
	ui.Successf(os.Stderr, "added new host key to known_hosts: %s", hostname)
	return nil
}
