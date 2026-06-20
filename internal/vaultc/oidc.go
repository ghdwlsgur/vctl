package vaultc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"
)

// oidcRedirect 는 Vault OIDC 헬퍼 표준 콜백 주소다(Vault CLI 와 동일).
const oidcRedirect = "http://localhost:8250/oidc/callback"

// LoginOIDC 는 브라우저 SSO(authorization code) 흐름으로 로그인한다.
//
// phase 2: Vault 에 OIDC auth (GitLab IdP) 가 활성화되면 동작한다.
//
//	vctl login --method oidc  →  브라우저 → SSO → 그룹→정책 매핑 → 토큰
func (c *Client) LoginOIDC(ctx context.Context, mount, role string) error {
	// 1) Vault 에서 인가 URL 발급
	sec, err := c.api.Logical().WriteWithContext(ctx, "auth/"+mount+"/oidc/auth_url", map[string]interface{}{
		"role":         role,
		"redirect_uri": oidcRedirect,
	})
	if err != nil {
		return fmt.Errorf("oidc auth_url: %w", err)
	}
	if sec == nil || sec.Data == nil {
		return fmt.Errorf("oidc auth_url: 빈 응답")
	}
	authURL, _ := sec.Data["auth_url"].(string)
	if authURL == "" {
		return fmt.Errorf("oidc: auth_url 비어있음 (Vault OIDC 가 설정되지 않았을 수 있음)")
	}

	// 2) 로컬 콜백 서버 기동
	type result struct {
		params map[string]string
		err    error
	}
	resCh := make(chan result, 1)
	ln, err := net.Listen("tcp", "localhost:8250")
	if err != nil {
		return fmt.Errorf("oidc 콜백 포트(8250) 바인드 실패: %w", err)
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
		_, _ = w.Write([]byte("<html><body>vctl 로그인 완료. 이 창을 닫아도 됩니다.</body></html>"))
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

	// 3) 브라우저 열기
	fmt.Println("브라우저에서 SSO 로그인을 진행하세요. 안 열리면 아래 URL 을 직접 여세요:")
	fmt.Println("  " + authURL)
	_ = openBrowser(authURL)

	// 4) 콜백 대기
	var got result
	select {
	case got = <-resCh:
	case <-time.After(3 * time.Minute):
		return fmt.Errorf("oidc: 콜백 타임아웃(3분)")
	case <-ctx.Done():
		return ctx.Err()
	}
	if got.err != nil {
		return got.err
	}

	// 5) 콜백 파라미터를 Vault 로 교환 → 토큰
	cb, err := c.api.Logical().ReadWithDataWithContext(ctx, "auth/"+mount+"/oidc/callback", map[string][]string{
		"state":    {got.params["state"]},
		"code":     {got.params["code"]},
		"id_token": {got.params["id_token"]},
	})
	if err != nil {
		return fmt.Errorf("oidc callback 교환: %w", err)
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
