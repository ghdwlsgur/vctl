package sshc

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testHostKey returns a fresh public key to stand in for a host's.
func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	return k
}

// isolatedHome points the callback at a scratch known_hosts. Without this the
// tests would read and append to the developer's real ~/.ssh/known_hosts.
func isolatedHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return filepath.Join(home, ".ssh", "known_hosts")
}

func addr(t *testing.T) net.Addr {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", "192.0.2.10:22")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return a
}

// This is the one that matters. A host whose key changed is either a rebuilt
// machine or someone sitting in the middle, and the callback cannot tell them
// apart — so it must refuse either way. Every other branch here is about
// convenience; this one is the reason host key checking exists at all.
func TestHostKeyCallbackRejectsAChangedKeyForAKnownHost(t *testing.T) {
	kh := isolatedHome(t)

	original := testHostKey(t)
	if err := os.MkdirAll(filepath.Dir(kh), 0o700); err != nil {
		t.Fatal(err)
	}
	line := "[192.0.2.10]:22 " + original.Type() + " " + base64Key(original) + "\n"
	if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	// autoAdd is on, which is the most permissive mode the callback offers.
	// Even there a mismatch must not be recorded over the old key.
	cb := hostKeyCallback(true, true)
	impostor := testHostKey(t)
	if err := cb("[192.0.2.10]:22", addr(t), impostor); err == nil {
		t.Fatal("a changed host key was accepted")
	}

	b, err := os.ReadFile(kh)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), base64Key(impostor)) {
		t.Error("the rejected key was written to known_hosts anyway")
	}
}

// accept-new: an unknown host is recorded on first sight. vctl mcp and other
// non-interactive callers depend on this, because they have no terminal to
// prompt at.
func TestHostKeyCallbackRecordsUnknownHostWhenAutoAddIsOn(t *testing.T) {
	kh := isolatedHome(t)
	key := testHostKey(t)

	cb := hostKeyCallback(false, true)
	if err := cb("[192.0.2.10]:22", addr(t), key); err != nil {
		t.Fatalf("accept-new rejected an unknown host: %v", err)
	}

	b, err := os.ReadFile(kh)
	if err != nil {
		t.Fatalf("known_hosts was not written: %v", err)
	}
	if !strings.Contains(string(b), base64Key(key)) {
		t.Error("the accepted key was not recorded")
	}
}

// Without autoAdd, a caller that cannot prompt must fail closed. Tests run
// without a terminal, which is exactly the condition being asserted: silently
// trusting here would make every automated path trust-on-first-use.
func TestHostKeyCallbackRefusesUnknownHostWithoutATerminal(t *testing.T) {
	kh := isolatedHome(t)
	key := testHostKey(t)

	cb := hostKeyCallback(true, false)
	err := cb("[192.0.2.10]:22", addr(t), key)
	if err == nil {
		t.Fatal("an unknown host was accepted with no way to confirm it")
	}
	if !strings.Contains(err.Error(), "connect interactively") {
		t.Errorf("error %q does not tell the operator how to proceed", err)
	}
	if b, err := os.ReadFile(kh); err == nil && strings.Contains(string(b), base64Key(key)) {
		t.Error("an unconfirmed key was recorded")
	}
}

// rejectHostKey is what the callback degrades to when known_hosts cannot be
// loaded at all. It must fail every check rather than wave connections through,
// because the alternative is losing host verification without saying so.
func TestRejectHostKeyFailsEveryHost(t *testing.T) {
	cb := rejectHostKey(errNotLoadable{})
	for _, host := range []string{"a.example", "b.example"} {
		if err := cb(host, addr(t), testHostKey(t)); err == nil {
			t.Errorf("rejectHostKey accepted %s", host)
		}
	}
}

type errNotLoadable struct{}

func (errNotLoadable) Error() string { return "known_hosts unavailable" }

func base64Key(k ssh.PublicKey) string {
	return strings.TrimSpace(strings.TrimPrefix(string(ssh.MarshalAuthorizedKey(k)), k.Type()+" "))
}
