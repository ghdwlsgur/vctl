package nodeaccess

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/net/websocket"
	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/config"
)

// ConnectShell opens an audited gateway PTY session. The caller supplies its
// operator Vault token; no SSH private key or guest address is used here.
func ConnectShell(ctx context.Context, gateway, token, target string, stdin, stdout *os.File) error {
	if _, err := NodeURI(target); err != nil {
		return fmt.Errorf("invalid host or VM identity: %w", err)
	}
	if stdin == nil || stdout == nil || !term.IsTerminal(int(stdin.Fd())) || !term.IsTerminal(int(stdout.Fd())) {
		return fmt.Errorf("node-access shell requires an interactive terminal")
	}
	parsed, err := url.Parse(gateway)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("gateway URL must be an https URL without credentials, query, or fragment")
	}
	parsed.Scheme = "wss"
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/v1/sessions/shell"
	query := parsed.Query()
	query.Set("node", target)
	parsed.RawQuery = query.Encode()
	origin := &url.URL{Scheme: "https", Host: parsed.Host}
	wsConfig, err := websocket.NewConfig(parsed.String(), origin.String())
	if err != nil {
		return err
	}
	wsConfig.Header.Set("Authorization", "Bearer "+token)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(config.SRERootCA) {
		return fmt.Errorf("embedded gateway CA bundle is invalid")
	}
	wsConfig.TlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		// x/net/websocket performs the RFC 6455 HTTP/1.1 Upgrade handshake.
		NextProtos: []string{"http/1.1"},
	}
	conn, err := wsConfig.DialContext(ctx)
	if err != nil {
		return fmt.Errorf("connect to shell gateway: %w", err)
	}
	defer conn.Close()
	conn.MaxPayloadBytes = maxShellFrame
	raw, err := term.MakeRaw(int(stdin.Fd()))
	if err != nil {
		return fmt.Errorf("set terminal raw mode: %w", err)
	}
	defer func() { _ = term.Restore(int(stdin.Fd()), raw) }()

	var writeMu sync.Mutex
	send := func(message ShellMessage) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return websocket.JSON.Send(conn, message)
	}
	if columns, rows, err := term.GetSize(int(stdout.Fd())); err == nil {
		if err := send(ShellMessage{Type: "resize", Columns: uint16(columns), Rows: uint16(rows)}); err != nil {
			return err
		}
	}
	inputErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 16<<10)
		for {
			n, readErr := stdin.Read(buffer)
			if n > 0 {
				payload := append([]byte(nil), buffer[:n]...)
				if err := send(ShellMessage{Type: "input", Data: payload}); err != nil {
					inputErr <- err
					return
				}
			}
			if readErr != nil {
				if readErr == io.EOF {
					_ = send(ShellMessage{Type: "close"})
					inputErr <- io.EOF
				} else {
					inputErr <- readErr
				}
				return
			}
		}
	}()
	winsize := make(chan os.Signal, 1)
	signal.Notify(winsize, syscall.SIGWINCH)
	defer func() { signal.Stop(winsize); close(winsize) }()
	go func() {
		for range winsize {
			columns, rows, err := term.GetSize(int(stdout.Fd()))
			if err == nil {
				_ = send(ShellMessage{Type: "resize", Columns: uint16(columns), Rows: uint16(rows)})
			}
		}
	}()
	for {
		var message ShellMessage
		if err := websocket.JSON.Receive(conn, &message); err != nil {
			if err == io.EOF {
				return nil
			}
			select {
			case inputError := <-inputErr:
				if inputError == io.EOF {
					return nil
				}
			default:
			}
			return fmt.Errorf("shell stream closed: %w", err)
		}
		switch message.Type {
		case "started":
		case "output":
			if _, err := stdout.Write(message.Data); err != nil {
				return err
			}
		case "exit":
			return nil
		case "error":
			return fmt.Errorf("remote shell: %s", message.Error)
		default:
			return fmt.Errorf("unexpected shell gateway message %q", message.Type)
		}
	}
}
