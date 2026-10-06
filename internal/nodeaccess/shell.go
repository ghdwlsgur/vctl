package nodeaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"golang.org/x/net/websocket"
)

const maxShellFrame = 64 << 10

// ShellMessage is the bounded control/data envelope used inside an already
// authenticated WebSocket. Data is base64 encoded by encoding/json.
type ShellMessage struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id,omitempty"`
	Data      []byte `json:"data,omitempty"`
	Columns   uint16 `json:"columns,omitempty"`
	Rows      uint16 `json:"rows,omitempty"`
	ExitCode  int    `json:"exit_code,omitempty"`
	Error     string `json:"error,omitempty"`
}

type shellPeer struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func (p *shellPeer) send(message ShellMessage) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return websocket.JSON.Send(p.conn, message)
}

func receiveShellMessage(conn *websocket.Conn) (ShellMessage, error) {
	var message ShellMessage
	if err := websocket.JSON.Receive(conn, &message); err != nil {
		return ShellMessage{}, err
	}
	if len(message.Data) > maxShellFrame {
		return ShellMessage{}, fmt.Errorf("shell data frame exceeds %d bytes", maxShellFrame)
	}
	return message, nil
}

func runPTYSession(ctx context.Context, peer *shellPeer, start ShellMessage) error {
	if start.Type != "start" || start.SessionID == "" {
		return fmt.Errorf("invalid shell start message")
	}
	defer peer.conn.Close()
	if err := peer.send(ShellMessage{Type: "started", SessionID: start.SessionID}); err != nil {
		return err
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	input := make(chan ShellMessage)
	readErr := make(chan error, 1)
	go func() {
		for {
			message, err := receiveShellMessage(peer.conn)
			if err != nil {
				readErr <- err
				cancel()
				return
			}
			if message.SessionID != start.SessionID {
				continue
			}
			select {
			case input <- message:
			case <-sessionCtx.Done():
				return
			}
			if message.Type == "close" {
				return
			}
		}
	}()
	output := &shellWriter{send: func(data []byte) error {
		return peer.send(ShellMessage{Type: "output", SessionID: start.SessionID, Data: data})
	}}
	code, err := runLocalPTY(sessionCtx, int(start.Columns), int(start.Rows), input, output)
	if err != nil {
		_ = peer.send(ShellMessage{Type: "error", SessionID: start.SessionID, Error: err.Error()})
		return err
	}
	if err := peer.send(ShellMessage{Type: "exit", SessionID: start.SessionID, ExitCode: code}); err != nil {
		return err
	}
	select {
	case err := <-readErr:
		if err != nil && err != io.EOF {
			return err
		}
	default:
	}
	return nil
}

type shellWriter struct {
	mu   sync.Mutex
	send func([]byte) error
}

func (w *shellWriter) Write(data []byte) (int, error) {
	const chunkSize = 24 << 10
	original := len(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	for len(data) > 0 {
		n := len(data)
		if n > chunkSize {
			n = chunkSize
		}
		if err := w.send(data[:n]); err != nil {
			return 0, err
		}
		data = data[n:]
	}
	return original, nil
}

func decodeShellJSON(data []byte, target any) error {
	if len(data) > maxShellFrame {
		return fmt.Errorf("shell message exceeds %d bytes", maxShellFrame)
	}
	return json.Unmarshal(data, target)
}
