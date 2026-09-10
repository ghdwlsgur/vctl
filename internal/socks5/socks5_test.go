package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// A client speaks the protocol by hand: greeting, CONNECT to a domain name,
// then bytes flow to an echo server the dialer reached.
func TestConnectByDomainReachesTheDialer(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	var asked string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		asked = address // the name arrives unresolved: socks5h semantics
		return net.Dial("tcp", echo.Addr().String())
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, ln, dial) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// greeting
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil || rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("greeting reply = %v, %v", rep, err)
	}
	// CONNECT api.example.internal:6443
	host := "api.example.internal"
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, []byte(host)...)
	req = binary.BigEndian.AppendUint16(req, 6443)
	_, _ = c.Write(req)
	rep = make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("connect reply = %v, %v", rep, err)
	}
	if asked != "api.example.internal:6443" {
		t.Errorf("dialer was asked for %q; the name must reach it unresolved", asked)
	}
	_, _ = c.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestRefusesWhatItDoesNotDo(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, io.EOF }
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, ln, dial) }()

	// Only username/password offered → no acceptable method.
	c, _ := net.Dial("tcp", ln.Addr().String())
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x02})
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0xff {
		t.Errorf("auth-only client got %v, %v; want method 0xff", rep, err)
	}
	c.Close()

	// BIND is not CONNECT.
	c, _ = net.Dial("tcp", ln.Addr().String())
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	_, _ = io.ReadFull(c, rep)
	_, _ = c.Write([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})
	rep = make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x07 {
		t.Errorf("BIND got reply %v, %v; want 0x07 command not supported", rep, err)
	}
	c.Close()

	// A dialer that fails is a host-unreachable reply, not a hang.
	c, _ = net.Dial("tcp", ln.Addr().String())
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	_, _ = io.ReadFull(c, rep[:2])
	_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x1f, 0x90})
	if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x04 {
		t.Errorf("failed dial got reply %v, %v; want 0x04 host unreachable", rep, err)
	}
	c.Close()
}

func TestForwardIsAFixedPipe(t *testing.T) {
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	var target string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		target = address
		return net.Dial("tcp", echo.Addr().String())
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Forward(ctx, ln, "10.0.0.9:6443", dial) }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("x"))
	buf := make([]byte, 1)
	if _, err := io.ReadFull(c, buf); err != nil || buf[0] != 'x' {
		t.Fatal("forward did not pipe")
	}
	if target != "10.0.0.9:6443" {
		t.Errorf("forward dialed %q", target)
	}
}
