# OIDC SSO 전환 (phase 2)

목표: 팀원당 Vault 계정 생성 없이, `vctl login` → 브라우저 SSO → 그룹→정책 자동 매핑.

GitLab(`gitlab.sre.local`)을 IdP로 쓴다고 가정한다.

```bash
# 1) GitLab 에 OIDC 애플리케이션 등록
#    Redirect URI:  http://localhost:8250/oidc/callback
#    Scopes:        openid, profile, email
#    → client_id / client_secret 확보

# 2) Vault OIDC auth 활성
vault auth enable oidc

vault write auth/oidc/config \
  oidc_discovery_url="https://gitlab.sre.local" \
  oidc_client_id="<client_id>" \
  oidc_client_secret="<client_secret>" \
  default_role="vctl"

# 3) role — 그룹 클레임을 받아 정책에 매핑
vault write auth/oidc/role/vctl \
  user_claim="sub" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  bound_audiences="<client_id>" \
  oidc_scopes="openid,profile,email,groups" \
  groups_claim="groups" \
  policies="vctl-user"

# 4) (선택) GitLab 그룹 → Vault 정책 매핑
#    external group 'sre-team' 멤버 → vctl-user / 'sre-admins' → vctl-admin
```

전환 후 클라이언트 기본값을 바꾼다:

```yaml
# .vctl/config.yaml  또는 바이너리 기본값(config.Defaults)
auth_method: oidc
```

코드는 이미 `vctl login --method oidc` 로 위 흐름(`internal/vaultc/oidc.go`)을 수행한다.
별도 구현 없이 Vault 설정만으로 동작한다.
