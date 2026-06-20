// Package sshc 는 Vault 서명 인증서로 네이티브 SSH 접속을 수행한다(시스템 ssh 불필요).
//
// 접속마다 ed25519 키쌍을 메모리에서 생성하고, 그 공개키를 Vault 로 서명받아
// 단명 cert 를 만든다 — 개인키는 디스크에 절대 닿지 않는다. 점프 체인은 홉마다
// 같은 절차를 그 홉의 유저로 재귀 수행한다.
package sshc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// SignFunc 는 authorized-key 형식 공개키를 받아 OpenSSH cert 문자열을 돌려준다.
type SignFunc func(role, publicKey string, principals []string) (cert string, err error)

// Target 은 접속 대상 한 홉을 기술한다. Jump 가 있으면 그 홉을 먼저 거친다.
type Target struct {
	Name string
	Addr string // host:port
	User string
	Role string // ssh/sign/<role>
	Jump *Target
}

// Connect 는 대상에 PTY 셸로 접속하고 종료까지 블록한다.
func Connect(ctx context.Context, t *Target, sign SignFunc) error {
	client, cleanup, err := dial(ctx, t, sign)
	if err != nil {
		return err
	}
	defer cleanup() // 대상 + 점프 체인 전체를 닫는다
	return shell(client)
}

// dial 은 대상 클라이언트와, 그 클라이언트 및 모든 상위 점프 연결을 닫는 cleanup 을 반환한다.
func dial(ctx context.Context, t *Target, sign SignFunc) (*ssh.Client, func(), error) {
	signer, err := certSigner(t.Role, t.User, sign)
	if err != nil {
		return nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback(),
		Timeout:         15 * time.Second,
	}

	if t.Jump == nil {
		client, err := ssh.Dial("tcp", t.Addr, cfg)
		if err != nil {
			return nil, nil, err
		}
		return client, func() { client.Close() }, nil
	}

	// 점프 홉을 먼저 연결한 뒤, 그 위에서 대상으로 터널링한다.
	jclient, jcleanup, err := dial(ctx, t.Jump, sign)
	if err != nil {
		return nil, nil, fmt.Errorf("점프(%s) 연결: %w", t.Jump.Name, err)
	}
	conn, err := jclient.Dial("tcp", t.Addr)
	if err != nil {
		jcleanup()
		return nil, nil, fmt.Errorf("점프 경유 %s 연결: %w", t.Addr, err)
	}
	ncc, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	if err != nil {
		jcleanup()
		return nil, nil, fmt.Errorf("%s 핸드셰이크: %w", t.Name, err)
	}
	client := ssh.NewClient(ncc, chans, reqs)
	// 대상 → 점프 순으로 닫는다.
	return client, func() { client.Close(); jcleanup() }, nil
}

// certSigner 는 메모리 키쌍을 만들고 Vault 서명 cert 로 signer 를 구성한다.
func certSigner(role, user string, sign SignFunc) (ssh.Signer, error) {
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

	certStr, err := sign(role, authKey, []string{user})
	if err != nil {
		return nil, err
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certStr))
	if err != nil {
		return nil, fmt.Errorf("서명 cert 파싱: %w", err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("서명 결과가 인증서가 아님")
	}
	return ssh.NewCertSigner(cert, base)
}

// shell 은 원격에 PTY 인터랙티브 셸을 띄운다(SIGWINCH 리사이즈 포함).
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
	// 정상 종료(exit code) 는 에러로 취급하지 않는다.
	var ee *ssh.ExitError
	if err != nil && asExitError(err, &ee) {
		return nil
	}
	return err
}

func asExitError(err error, target **ssh.ExitError) bool {
	if ee, ok := err.(*ssh.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

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
