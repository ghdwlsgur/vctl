package nodeaccess

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// SessionAgent maintains an outbound long-poll connection to the gateway and
// executes only the operations accepted by Request.Validate and Execute.
type SessionAgent struct {
	GatewayURL string
	TLS        *tls.Config
	Renewal    *CertificateRenewer
	OnError    func(error)
}

// Run reconnects with bounded backoff until the service context is cancelled.
func (a *SessionAgent) Run(ctx context.Context) error {
	base, err := agentGatewayURL(a.GatewayURL)
	if err != nil {
		return err
	}
	if a.TLS == nil || len(a.TLS.Certificates) == 0 || a.TLS.RootCAs == nil {
		return fmt.Errorf("node mTLS identity and gateway CA are required")
	}
	var identity atomic.Pointer[tls.Certificate]
	identity.Store(&a.TLS.Certificates[0])
	tlsConfig := a.TLS.Clone()
	tlsConfig.Certificates = nil
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert := identity.Load()
		if cert == nil {
			return nil, fmt.Errorf("node mTLS identity is unavailable")
		}
		return cert, nil
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true},
		Timeout:   35 * time.Second,
	}
	defer client.CloseIdleConnections()
	go a.runShellStream(ctx, base, tlsConfig)
	if a.Renewal != nil {
		a.Renewal.TLS = tlsConfig
		go a.Renewal.Run(ctx, &identity, a.OnError)
	}
	delay := time.Second
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := a.pollOnce(ctx, client, base)
		if err == nil {
			delay = time.Second
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		if a.OnError != nil {
			a.OnError(err)
		}
		if err := waitContext(ctx, delay); err != nil {
			return nil
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

func (a *SessionAgent) pollOnce(ctx context.Context, client *http.Client, base string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/agent/poll", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("poll access gateway: %w", err)
	}
	if response.StatusCode == http.StatusNoContent {
		response.Body.Close()
		return nil
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 8<<10))
		response.Body.Close()
		return fmt.Errorf("gateway poll returned %s: %s", response.Status, strings.TrimSpace(string(body)))
	}
	var requestMessage Request
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxRequestBody))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&requestMessage)
	response.Body.Close()
	if err != nil {
		return fmt.Errorf("decode gateway request: %w", err)
	}
	result, operationErr := Execute(ctx, requestMessage)
	if operationErr != nil {
		result.Error = operationErr.Error()
		if len(result.Error) > 8<<10 {
			result.Error = result.Error[:8<<10]
		}
	}
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode operation result: %w", err)
	}
	resultRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/agent/result", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resultRequest.Header.Set("Content-Type", "application/json")
	resultResponse, err := client.Do(resultRequest)
	if err != nil {
		return fmt.Errorf("send operation result: %w", err)
	}
	defer resultResponse.Body.Close()
	if resultResponse.StatusCode != http.StatusAccepted {
		message, _ := io.ReadAll(io.LimitReader(resultResponse.Body, 8<<10))
		return fmt.Errorf("gateway rejected operation result (%s): %s", resultResponse.Status, strings.TrimSpace(string(message)))
	}
	return nil
}

func agentGatewayURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("gateway URL must be an https URL without credentials, query, or fragment")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ctx.Err()
		}
		return ctx.Err()
	}
}
