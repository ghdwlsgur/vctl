// Package socks5 is the smallest SOCKS5 server that lets kubectl, ssh, curl
// and a browser reach through a dialer they cannot see: CONNECT only, no
// authentication, meant to listen on loopback. `vctl wg connect` puts one in
// front of its userspace WireGuard tunnel; HTTPS_PROXY=socks5h://127.0.0.1:1080
// or a kubeconfig proxy-url is then all a client needs.
//
// Names are passed to the dialer unresolved (socks5h semantics), so a
// fleet-internal hostname is resolved on the far side of whatever the dialer
// is — through the tunnel's DNS, not the workstation's.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
)

// Dialer opens the connection a client asked for. network is always "tcp".
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Serve accepts on ln until ctx is done or ln fails, handling each client in
// its own goroutine. It closes ln when ctx is done and returns ctx.Err().
func Serve(ctx context.Context, ln net.Listener, dial Dialer) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			handle(ctx, c, dial)
		}()
	}
}

// Forward accepts on ln and connects every client to target through dial —
// a fixed port-forward for a client that cannot speak SOCKS.
func Forward(ctx context.Context, ln net.Listener, target string, dial Dialer) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			far, err := dial(ctx, "tcp", target)
			if err != nil {
				return
			}
			defer far.Close()
			pipe(c, far)
		}()
	}
}

const (
	version      = 0x05
	methodNoAuth = 0x00
	methodNone   = 0xff
	cmdConnect   = 0x01
	atypIPv4     = 0x01
	atypDomain   = 0x03
	atypIPv6     = 0x04

	replyOK             = 0x00
	replyGeneralFailure = 0x01
	replyHostUnreach    = 0x04
	replyCmdUnsupported = 0x07
	replyAtypUnsupp     = 0x08
)

func handle(ctx context.Context, c net.Conn, dial Dialer) {
	// Greeting: VER NMETHODS METHODS…  →  VER METHOD
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != version {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	offered := false
	for _, m := range methods {
		if m == methodNoAuth {
			offered = true
		}
	}
	if !offered {
		_, _ = c.Write([]byte{version, methodNone})
		return
	}
	if _, err := c.Write([]byte{version, methodNoAuth}); err != nil {
		return
	}
	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != version {
		return
	}
	target, err := readAddr(c, req[3])
	if err != nil {
		reply(c, replyAtypUnsupp)
		return
	}
	if req[1] != cmdConnect {
		reply(c, replyCmdUnsupported)
		return
	}
	far, err := dial(ctx, "tcp", target)
	if err != nil {
		reply(c, replyHostUnreach)
		return
	}
	defer far.Close()
	reply(c, replyOK)
	pipe(c, far)
}

// readAddr reads DST.ADDR DST.PORT for one address type and returns host:port
// — a domain is returned as written, for the dialer to resolve.
func readAddr(r io.Reader, atyp byte) (string, error) {
	var host string
	switch atyp {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		n := make([]byte, 1)
		if _, err := io.ReadFull(r, n); err != nil {
			return "", err
		}
		b := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", fmt.Errorf("address type %#x is not supported", atyp)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p)))), nil
}

// reply sends VER REP RSV ATYP BND.ADDR BND.PORT with a zero bind address;
// clients do not use it for CONNECT.
func reply(c net.Conn, code byte) {
	_, _ = c.Write([]byte{version, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
}

// pipe copies both ways and returns when either side closes.
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// ErrNotSocks5 is what a probe returns for a listener that is not this server.
var ErrNotSocks5 = errors.New("not a SOCKS5 server")
