# vctl-user — 일반 팀원 정책
# SSH cert 서명 + 인벤토리 읽기 자격. 서버에 들어가는 데 필요한 최소 권한.

# 접속 cert 서명
path "ssh/sign/sre-core" {
  capabilities = ["update"]
}

# CA 공개키 읽기 (status/검증용)
path "ssh/config/ca" {
  capabilities = ["read"]
}

# 인벤토리 읽기용 단명 DB 자격
path "database/creds/vctl-ro" {
  capabilities = ["read"]
}

# 자기 토큰 점검
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# 자기 토큰 갱신 (vctl agent/exec/token 자동 renew-self)
path "auth/token/renew-self" {
  capabilities = ["update"]
}
