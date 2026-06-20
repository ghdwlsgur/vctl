// Package app 은 config·Vault·Store 를 엮어 CLI 명령들이 공유하는 진입점을 만든다.
package app

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/ghdwlsgur/vctl/internal/config"
	"github.com/ghdwlsgur/vctl/internal/store"
	"github.com/ghdwlsgur/vctl/internal/vaultc"
)

type App struct {
	Cfg   *config.Config
	Vault *vaultc.Client
}

func New() (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	v, err := vaultc.New(cfg.VaultAddr, config.SRERootCA, cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &App{Cfg: cfg, Vault: v}, nil
}

// EnsureLogin 은 에이전트처럼 토큰을 살린다:
//  1. 유효하면 그대로 사용
//  2. 갱신 가능하면 renew-self (자격 재입력 없음)
//  3. approle 자격이 있으면 무인 재인증
//  4. 그래도 안 되면 대화식 로그인
func (a *App) EnsureLogin(ctx context.Context) error {
	if a.Vault.HasValidToken() {
		return nil
	}
	if a.Vault.Renewable() && a.Vault.TTL() > 0 {
		if err := a.Vault.Renew(ctx); err == nil {
			return nil
		}
	}
	if id, sec, ok := a.AppRoleCreds(); ok {
		if err := a.Vault.LoginAppRole(ctx, a.Cfg.AppRoleMount, id, sec); err == nil {
			return nil
		}
	}
	return a.Login(ctx, a.Cfg.AuthMethod)
}

// Login 은 명시한 방식으로 로그인한다(userpass | oidc | approle).
func (a *App) Login(ctx context.Context, method string) error {
	switch strings.ToLower(method) {
	case "oidc":
		fmt.Fprintf(os.Stderr, "Vault OIDC SSO 로그인 (%s)...\n", a.Cfg.VaultAddr)
		return a.Vault.LoginOIDC(ctx, a.Cfg.OIDCMount, a.Cfg.OIDCRole)
	case "approle":
		id, sec, ok := a.AppRoleCreds()
		if !ok {
			return fmt.Errorf("approle 자격이 없습니다 (VCTL_ROLE_ID/VCTL_SECRET_ID 또는 *_FILE)")
		}
		return a.Vault.LoginAppRole(ctx, a.Cfg.AppRoleMount, id, sec)
	case "", "userpass":
		return a.loginUserpass(ctx)
	default:
		return fmt.Errorf("알 수 없는 인증 방식: %s", method)
	}
}

// ReAuth 는 현재 토큰을 무시하고 새 토큰을 받는다(갱신 불가 시 호출).
// approle 자격이 있으면 무인, 없으면 대화식.
func (a *App) ReAuth(ctx context.Context) error {
	if err := a.ReAuthNonInteractive(ctx); err == nil {
		return nil
	}
	return a.Login(ctx, a.Cfg.AuthMethod)
}

// ReAuthNonInteractive 는 대화식 프롬프트 없이 approle 로만 재인증한다.
// exec 처럼 stdin 을 자식이 점유한 상황에서 쓴다(프롬프트 충돌 방지).
// approle 자격이 없으면 에러를 돌려준다.
func (a *App) ReAuthNonInteractive(ctx context.Context) error {
	id, sec, ok := a.AppRoleCreds()
	if !ok {
		return fmt.Errorf("approle 자격이 없어 무인 재인증 불가")
	}
	return a.Vault.LoginAppRole(ctx, a.Cfg.AppRoleMount, id, sec)
}

// AppRoleCreds 는 설정값 또는 파일에서 role_id/secret_id 를 해석한다.
func (a *App) AppRoleCreds() (roleID, secretID string, ok bool) {
	roleID = firstNonEmpty(a.Cfg.AppRoleID, readFileTrim(a.Cfg.AppRoleIDFile))
	secretID = firstNonEmpty(a.Cfg.AppRoleSecretID, readFileTrim(a.Cfg.AppRoleSecretIDFile))
	return roleID, secretID, roleID != "" && secretID != ""
}

func readFileTrim(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func (a *App) loginUserpass(ctx context.Context) error {
	fmt.Fprintf(os.Stderr, "Vault 로그인 (%s)\n", a.Cfg.VaultAddr)
	reader := bufio.NewReader(os.Stdin)

	def := os.Getenv("USER")
	if def != "" {
		fmt.Fprintf(os.Stderr, "Username [%s]: ", def)
	} else {
		fmt.Fprint(os.Stderr, "Username: ")
	}
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		username = def
	}
	if username == "" {
		return fmt.Errorf("username 이 필요합니다")
	}

	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if err := a.Vault.LoginUserpass(ctx, username, string(pw)); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "로그인 성공.")
	return nil
}

// OpenStore 는 로그인 보장 → Vault 동적 DB 자격 발급 → Postgres 연결을 수행한다.
// rw=true 면 쓰기 role(sync/admin), 아니면 읽기 role.
func (a *App) OpenStore(ctx context.Context, rw bool) (*store.Store, error) {
	role := a.Cfg.DBRoleRO
	if rw {
		role = a.Cfg.DBRoleRW
	}
	return a.OpenStoreRole(ctx, role)
}

// OpenStoreRole 는 지정한 Vault database role 로 Postgres 연결을 연다.
func (a *App) OpenStoreRole(ctx context.Context, role string) (*store.Store, error) {
	if err := a.EnsureLogin(ctx); err != nil {
		return nil, err
	}
	user, pass, _, err := a.Vault.DBCreds(ctx, role)
	if err != nil {
		return nil, err
	}
	return store.Open(ctx, a.Cfg.DBHost, a.Cfg.DBPort, a.Cfg.DBName, user, pass, config.SRERootCA)
}
