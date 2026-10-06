package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ghdwlsgur/vctl/internal/app"
	"github.com/ghdwlsgur/vctl/internal/nodeaccess"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	listen := envOr("VCTL_ACCESS_LISTEN", ":8080")
	caFile := envOr("VCTL_ACCESS_NODE_CA_FILE", "/etc/vctl-access/node-ca.crt")
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read node client CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("node client CA bundle contains no certificates")
	}

	application, err := app.New()
	if err != nil {
		return fmt.Errorf("initialize vctl app: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := application.EnsureLogin(ctx); err != nil {
		return fmt.Errorf("authenticate gateway service: %w", err)
	}
	var enrollmentKey []byte
	if keyFile := strings.TrimSpace(os.Getenv("VCTL_ACCESS_ENROLLMENT_KEY_FILE")); keyFile != "" {
		enrollmentKey, err = os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("read VM enrollment signing key: %w", err)
		}
		if len(enrollmentKey) < 32 {
			return fmt.Errorf("VM enrollment signing key must contain at least 32 bytes")
		}
	}
	if application.Cfg.DBRoleNodeAccessAudit == "" {
		return fmt.Errorf("VCTL_DB_ROLE_NODE_ACCESS_AUDIT is required")
	}
	adapters := nodeaccess.VCTLAdapters{App: application}
	gateway, err := nodeaccess.NewGateway(adapters, adapters, adapters, roots)
	if err != nil {
		return err
	}
	gateway.VMIssuer = adapters
	gateway.NovaAuth = adapters
	gateway.EnrollmentKey = enrollmentKey
	gateway.GatewayURL = envOr("VCTL_ACCESS_PUBLIC_URL", "https://node-access.sre.local")
	gateway.AgentBinaryPath = envOr("VCTL_ACCESS_AGENT_BINARY_FILE", "/usr/local/bin/vctl-agent")
	defer gateway.Close()
	server := &http.Server{
		Addr:              listen,
		Handler:           gateway,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.ListenAndServe()
	}()
	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve node access gateway: %w", err)
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return fmt.Errorf("shutdown node access gateway: %w", err)
		}
		return nil
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
