package vaultc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	sec, err := c.writePath(ctx, "auth/"+mount+"/oidc/auth_url", map[string]interface{}{
		"role":         role,
		"redirect_uri": oidcRedirect,
	})
	if err != nil {
		return err
	}
	authURL, _ := sec.Data["auth_url"].(string)
	if authURL == "" {
		return fmt.Errorf("oidc: auth_url is empty; Vault OIDC may not be configured")
	}
	expectedState, err := oidcState(authURL)
	if err != nil {
		return err
	}

	// 2. Start a local callback server.
	type result struct {
		params map[string]string
		err    error
	}
	resCh := make(chan result, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:8250")
	if err != nil {
		return fmt.Errorf("oidc callback port 8250 bind failed: %w", err)
	}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
	}
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
		if params["state"] == "" || params["state"] != expectedState || (params["code"] == "" && params["id_token"] == "") {
			http.Error(w, "invalid OIDC callback", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(oidcDonePage))
		select {
		case resCh <- result{params: params}:
		default:
		}
	})
	srv.Handler = mux
	go func() {
		_ = srv.Serve(ln)
	}()
	// Shutdown, not Close: Close severs active connections at once, and the
	// callback response is still in flight when this returns. The browser needs
	// the whole page to arrive before it can render the confirmation or run the
	// close attempt, and a truncated response leaves the user on a blank tab
	// with a login that actually succeeded.
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

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

func oidcState(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("oidc auth_url parse: %w", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		return "", fmt.Errorf("oidc auth_url has no state")
	}
	return state, nil
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

// oidcDonePage is what the browser lands on after a successful callback.
//
// It asks the tab to close itself, but that request is usually refused.
// Browsers only honour window.close() for windows script opened, and this tab
// came from `open`/`xdg-open`/`rundll32` — a user-initiated navigation as far
// as the browser is concerned. Chrome and Firefox both ignore the call there.
//
// So the close attempt is the optimistic path, not the design. The page has to
// read correctly when nothing happens, which is the common case: it says the
// login finished and that the tab can be closed, and it says that whether or
// not the script succeeded. Writing it the other way — a blank page that
// assumes it will vanish — leaves the user staring at nothing wondering if the
// login worked.
const oidcDonePage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>vctl login complete</title>
<style>
  :root { color-scheme: light dark; }
  body {
    margin: 0; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
    background: #fafafa; color: #1a1a1a;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #16181d; color: #e6e6e6; }
    .card { background: #1e2128; border-color: #2c3038; }
    .hint { color: #9aa0aa; }
  }
  .card {
    background: #fff; border: 1px solid #e4e4e7; border-radius: 10px;
    padding: 28px 34px; text-align: center; max-width: 380px;
  }
  .mark { font-size: 26px; line-height: 1; }
  h1 { font-size: 16px; font-weight: 600; margin: 12px 0 6px; }
  .hint { font-size: 13px; color: #6b7280; margin: 0; }
</style>
</head>
<body>
  <div class="card">
    <div class="mark">✓</div>
    <h1>vctl login complete</h1>
    <p class="hint">You can close this tab and return to your terminal.</p>
  </div>
  <script>
    // Only works if this tab was opened by script; harmless when refused.
    setTimeout(function () { window.close(); }, 400);
  </script>
</body>
</html>
`
