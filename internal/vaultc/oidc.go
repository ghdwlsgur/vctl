package vaultc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/ghdwlsgur/vctl/internal/ui"
)

// oidcRedirect matches the standard Vault CLI helper callback URL.
const oidcRedirect = "http://localhost:8250/oidc/callback"

// LoginOIDC authenticates through browser SSO.
//
// It works once Vault OIDC auth is configured.
//
//	vctl login --method oidc -> browser -> SSO -> group policy mapping -> token
func (c *Client) LoginOIDC(ctx context.Context, mount, role string) error {
	// 1. Request the authorization URL from Vault.
	sec, err := c.api.Logical().WriteWithContext(ctx, "auth/"+mount+"/oidc/auth_url", map[string]interface{}{
		"role":         role,
		"redirect_uri": oidcRedirect,
	})
	if err != nil {
		return fmt.Errorf("oidc auth_url: %w", err)
	}
	if sec == nil || sec.Data == nil {
		return fmt.Errorf("oidc auth_url: empty response")
	}
	authURL, _ := sec.Data["auth_url"].(string)
	if authURL == "" {
		return fmt.Errorf("oidc: auth_url is empty; Vault OIDC may not be configured")
	}

	// 2. Start a local callback server.
	type result struct {
		params map[string]string
		err    error
	}
	resCh := make(chan result, 1)
	ln, err := net.Listen("tcp", "localhost:8250")
	if err != nil {
		return fmt.Errorf("oidc callback port 8250 bind failed: %w", err)
	}
	srv := &http.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oidc/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		params := map[string]string{
			"state":    q.Get("state"),
			"code":     q.Get("code"),
			"id_token": q.Get("id_token"),
		}
		if params["state"] == "" || (params["code"] == "" && params["id_token"] == "") {
			http.Error(w, "invalid OIDC callback", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("<html><body>vctl login complete. You can close this window.</body></html>"))
		select {
		case resCh <- result{params: params}:
		default:
		}
	})
	srv.Handler = mux
	go func() {
		_ = srv.Serve(ln)
	}()
	defer srv.Close()

	// 3. Open the browser.
	ui.Infof(os.Stdout, "complete SSO login in your browser")
	ui.Infof(os.Stdout, "if it does not open, use this URL: %s", authURL)
	_ = openBrowser(authURL)

	// 4. Wait for the callback.
	var got result
	select {
	case got = <-resCh:
	case <-time.After(3 * time.Minute):
		return fmt.Errorf("oidc: callback timeout after 3 minutes")
	case <-ctx.Done():
		return ctx.Err()
	}
	if got.err != nil {
		return got.err
	}

	// 5. Exchange callback parameters with Vault.
	cb, err := c.api.Logical().ReadWithDataWithContext(ctx, "auth/"+mount+"/oidc/callback", map[string][]string{
		"state":    {got.params["state"]},
		"code":     {got.params["code"]},
		"id_token": {got.params["id_token"]},
	})
	if err != nil {
		return fmt.Errorf("oidc callback exchange: %w", err)
	}
	return c.applyAuth(cb)
}

func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}
