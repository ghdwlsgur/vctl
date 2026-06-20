# vctl-admin — 관리자 정책 (sync/인벤토리 쓰기 + CA 운영)
# vctl-user 의 모든 권한 + 쓰기 자격 + CA 로테이션.

path "ssh/sign/sre-core" {
  capabilities = ["update"]
}

path "ssh/config/ca" {
  capabilities = ["read", "update"]
}

# 인벤토리 읽기/쓰기 자격
path "database/creds/vctl-ro" {
  capabilities = ["read"]
}
path "database/creds/vctl-rw" {
  capabilities = ["read"]
}
path "database/creds/vctl-migrator" {
  capabilities = ["read"]
}

# DB 엔진 root 자격 로테이션
path "database/rotate-root/vctl-pg" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
