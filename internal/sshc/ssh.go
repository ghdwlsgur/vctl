// Package sshc opens native SSH sessions with Vault-signed certificates.
//
// Each connection generates an in-memory ed25519 keypair, asks Vault to sign
// the public key, and keeps the private key off disk. Jump chains repeat the
// same process per hop.
package sshc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// SignFunc signs an authorized-key public key and returns an OpenSSH cert.
type SignFunc func(role, publicKey string, principals []string, extensions []string) (cert string, err error)

var (
	ptyExtensions         = []string{"permit-pty"}
	portForwardExtensions = []string{"permit-port-forwarding"}
)

// Target describes one SSH hop. Jump is dialed first when set.
type Target struct {
	Name           string
	Addr           string // host:port
	User           string
	Role           string // ssh/sign/<role>
	SkipDirect     bool   // connect through Jump without first trying the target directly
	ConfirmHostKey bool   // allow an interactive prompt for a previously unknown host key
	AutoAddHostKey bool   // non-interactive: record an unknown host key on first use (accept-new) instead of rejecting
	Jump           *Target
}

// ConnectionInfo describes the client-side network path used for an SSH session.
type ConnectionInfo struct {
	SourceAddr string
	SourceIP   string
	TargetAddr string
	ViaJump    bool
	JumpHost   string
}

// Connect opens an interactive PTY shell and blocks until it exits.
//
// afterDial, when non-nil, is called once the connection is established and
// before the shell blocks. It exists so the caller can record the access the
// instant it happens rather than after a session that may run for hours or end
// with the process being killed — either of which would otherwise leave no
// audit trail. It must not block for long: the shell does not start until it
// returns.
func Connect(ctx context.Context, t *Target, sign SignFunc, afterDial func(ConnectionInfo)) (ConnectionInfo, error) {
	client, cleanup, info, err := dialTarget(ctx, t, sign)
	if err != nil {
		return info, err
	}
	defer cleanup()
	if afterDial != nil {
		afterDial(info)
	}
	return info, shell(client)
}

// RunResult is the outcome of a one-shot remote command (no PTY).
type RunResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// RunWithInput executes a single command on the target non-interactively,
// capturing stdout/stderr/exit code, with the command's stdin wired to input
// — how an installer streams a file into `cat > path` on the far side without
// a second transport, a temp file, or shell-quoting the payload; nil means no
// stdin. It reuses dialTarget, so the jump chain and Vault-signed-cert auth
// are identical to Connect — this is the path automation and AI agents (vctl
// mcp) use instead of an interactive shell. A non-zero exit is returned in
// RunResult.ExitCode with a nil error (the command ran); only a
// transport/connection failure returns a non-nil error.
func RunWithInput(ctx context.Context, t *Target, sign SignFunc, command string, input io.Reader) (RunResult, ConnectionInfo, error) {
	client, cleanup, info, err := dialTarget(ctx, t, sign)
	if err != nil {
		return RunResult{}, info, err
	}
	defer cleanup()

	sess, err := client.NewSession()
	if err != nil {
		return RunResult{}, info, err
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	if input != nil {
		sess.Stdin = input
	}

	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	select {
	case <-ctx.Done():
		// SIGKILL is best-effort (OpenSSH ignores signals on non-PTY exec), so
		// close the session to actually unblock sess.Run, then wait for the
		// goroutine to stop writing the buffers before reading them (no race).
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		<-done
		return RunResult{Stdout: stdout.String(), Stderr: stderr.String()}, info, ctx.Err()
	case runErr := <-done:
		res := RunResult{Stdout: stdout.String(), Stderr: stderr.String()}
		var ee *ssh.ExitError
		if errors.As(runErr, &ee) {
			res.ExitCode = ee.ExitStatus() // command ran, non-zero exit
			return res, info, nil
		}
		return res, info, runErr
	}
}

// dialTarget prefers direct SSH, then falls back to the configured jump chain.
func dialTarget(ctx context.Context, t *Target, sign SignFunc) (*ssh.Client, func(), ConnectionInfo, error) {
	// dialJump connects via the jump chain; connectionInfo(nil, …) builds the
	// failure info (addr + ViaJump + JumpHost) so error paths don't reassemble it.
	dialJump := func() (*ssh.Client, func(), ConnectionInfo, error) {
		client, cleanup, err := dialChain(ctx, t, sign, ptyExtensions)
		if err != nil {
			return nil, nil, connectionInfo(nil, t, true), err
		}
		return client, cleanup, connectionInfo(client, t, true), nil
	}

	// SkipDirect with a jump available: go straight to the jump chain.
	if t.SkipDirect && t.Jump != nil {
		return dialJump()
	}

	// Otherwise try direct first.
	client, cleanup, directErr := dialSingle(t, sign, ptyExtensions)
	if directErr == nil || t.Jump == nil {
		// success, or no jump to fall back to — return the direct result as-is.
		return client, cleanup, connectionInfo(client, t, false), directErr
	}

	// Direct failed but a jump exists: fall back, wrapping both errors if it fails.
	client, cleanup, info, jumpErr := dialJump()
	if jumpErr != nil {
		return nil, nil, info, fmt.Errorf("direct connection failed: %v; jump connection failed: %w", directErr, jumpErr)
	}
	return client, cleanup, info, nil
}

func connectionInfo(client *ssh.Client, t *Target, viaJump bool) ConnectionInfo {
	info := ConnectionInfo{TargetAddr: t.Addr, ViaJump: viaJump}
	if t.Jump != nil && viaJump {
		info.JumpHost = t.Jump.Name
	}
	if client == nil {
		return info
	}
	if addr := client.LocalAddr(); addr != nil {
		info.SourceAddr = addr.String()
		info.SourceIP = addrIP(addr)
	}
	return info
}

func addrIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	return ""
}

func dialSingle(t *Target, sign SignFunc, extensions []string) (*ssh.Client, func(), error) {
	cfg, err := clientConfig(t, sign, extensions)
	if err != nil {
		return nil, nil, err
	}
	client, err := ssh.Dial("tcp", t.Addr, cfg)
	if err != nil {
		return nil, nil, err
	}
	return client, func() { client.Close() }, nil
}

// dialChain dials t through its jump chain. The hop being dialed (t) gets
// leafExtensions on its cert; intermediate jump hosts always get
// portForwardExtensions (the target gets ptyExtensions, jump hosts only need to
// forward). With t.Jump == nil it is a direct single dial.
func dialChain(ctx context.Context, t *Target, sign SignFunc, leafExtensions []string) (*ssh.Client, func(), error) {
	if t.Jump == nil {
		return dialSingle(t, sign, leafExtensions)
	}

	jclient, jcleanup, err := dialChain(ctx, t.Jump, sign, portForwardExtensions)
	if err != nil {
		return nil, nil, fmt.Errorf("jump %s connection: %w", t.Jump.Name, err)
	}
	conn, err := jclient.Dial("tcp", t.Addr)
	if err != nil {
		jcleanup()
		return nil, nil, fmt.Errorf("connect through jump to %s: %w", t.Addr, err)
	}
	cfg, err := clientConfig(t, sign, leafExtensions)
	if err != nil {
		jcleanup()
		return nil, nil, err
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	if err != nil {
		jcleanup()
		return nil, nil, fmt.Errorf("%s handshake: %w", t.Name, err)
	}
	client := ssh.NewClient(ncc, chans, reqs)
	// Close target before jump.
	return client, func() { client.Close(); jcleanup() }, nil
}

func clientConfig(t *Target, sign SignFunc, extensions []string) (*ssh.ClientConfig, error) {
	signer, err := certSigner(t.Role, t.User, sign, extensions)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback(t.ConfirmHostKey, t.AutoAddHostKey),
		// Prefer ed25519 to match OpenSSH's default host-key order. x/crypto's
		// default prefers ECDSA/RSA, so vctl would negotiate a different host
		// key type than `ssh` and trip a false "knownhosts: key mismatch" when
		// known_hosts only has the ed25519 entry that `ssh` recorded.
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA,
		},
		Timeout: 15 * time.Second,
	}, nil
}

// certSigner creates an in-memory keypair and wraps it with a Vault cert.
func certSigner(role, user string, sign SignFunc, extensions []string) (ssh.Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	base, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	authKey := string(ssh.MarshalAuthorizedKey(sshPub))

	certStr, err := sign(role, authKey, []string{user}, extensions)
	if err != nil {
		return nil, err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		return nil, fmt.Errorf("parse signed cert: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("signed result is not a certificate")
	}
	return ssh.NewCertSigner(cert, base)
}

// CertSerial parses an OpenSSH certificate string and returns its serial as a
// decimal string. It returns "" when the input is not a parseable certificate.
// Used for access audit logging so a signed access maps to a Vault-issued serial.
func CertSerial(certStr string) string {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		return ""
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return ""
	}
	return strconv.FormatUint(cert.Serial, 10)
}

// shell opens an interactive remote PTY and handles SIGWINCH resize events.
func shell(client *ssh.Client) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	fd := int(os.Stdin.Fd())
	var oldState *term.State
	if term.IsTerminal(fd) {
		oldState, err = term.MakeRaw(fd)
		if err != nil {
			return err
		}
		defer term.Restore(fd, oldState)
	}

	w, h := 80, 24
	if term.IsTerminal(fd) {
		if cw, ch, err := term.GetSize(fd); err == nil {
			w, h = cw, ch
		}
	}
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty(termType, h, w, modes); err != nil {
		return err
	}

	sess.Stdin = os.Stdin
	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr

	if term.IsTerminal(fd) {
		go watchResize(sess, fd)
	}

	if err := sess.Shell(); err != nil {
		return err
	}
	err = sess.Wait()
	// Treat remote exit codes as normal shell termination.
	var ee *ssh.ExitError
	if err != nil && errors.As(err, &ee) {
		return nil
	}
	return err
}

// IsAuthFailure reports whether an error is the server refusing the identity —
// the certificate's user does not exist there, or the CA is not trusted — as
// opposed to the network or the handshake mechanics failing. Callers walking
// login-user candidates advance on this and only this: retrying a different
// user over a dead route learns nothing and costs a certificate per try.
//
// A substring of x/crypto/ssh's error, because the library exposes no typed
// value for it; the string is stable across the versions this module has
// vendored and is asserted by a test.
func IsAuthFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "unable to authenticate")
}
