package nodeaccess

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

func (a *SessionAgent) runShellStream(ctx context.Context, base string, tlsConfig *tls.Config) {
	delay := time.Second
	for ctx.Err() == nil {
		conn, err := dialAgentShell(ctx, base, tlsConfig)
		if err == nil {
			conn.MaxPayloadBytes = maxShellFrame
			closed := make(chan struct{})
			go func() {
				select {
				case <-ctx.Done():
					_ = conn.Close()
				case <-closed:
				}
			}()
			err = serveAgentShellStream(ctx, &shellPeer{conn: conn})
			close(closed)
			_ = conn.Close()
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && a.OnError != nil {
			a.OnError(fmt.Errorf("shell stream: %w", err))
		}
		if err := waitContext(ctx, delay); err != nil {
			return
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

func dialAgentShell(ctx context.Context, base string, tlsConfig *tls.Config) (*websocket.Conn, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("invalid shell gateway URL")
	}
	origin := &url.URL{Scheme: "https", Host: u.Host}
	u.Scheme = "wss"
	u.Path = strings.TrimRight(u.Path, "/") + "/v1/agent/stream"
	config, err := websocket.NewConfig(u.String(), origin.String())
	if err != nil {
		return nil, err
	}
	config.TlsConfig = tlsConfig.Clone()
	// x/net/websocket uses the HTTP/1.1 Upgrade handshake. Some TLS
	// terminators advertise HTTP/2 by default; pin the WebSocket connection to
	// HTTP/1.1 so they do not send HTTP/2 frames to the Upgrade client.
	config.TlsConfig.NextProtos = []string{"http/1.1"}
	conn, err := config.DialContext(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func serveAgentShellStream(ctx context.Context, peer *shellPeer) error {
	defer peer.conn.Close()
	if err := peer.send(ShellMessage{Type: "ready"}); err != nil {
		return err
	}
	heartbeatDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(45 * time.Second)
		defer ticker.Stop()
		defer close(heartbeatDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if peer.send(ShellMessage{Type: "heartbeat"}) != nil {
					return
				}
			}
		}
	}()
	defer func() { <-heartbeatDone }()
	for {
		message, err := receiveShellMessage(peer.conn)
		if err != nil {
			return err
		}
		switch message.Type {
		case "heartbeat":
		case "start":
			if err := runPTYSession(ctx, peer, message); err != nil {
				return err
			}
			return nil // the PTY session closes this socket; reconnect for the next one
		default:
			return fmt.Errorf("unexpected shell control message %q", message.Type)
		}
	}
}
