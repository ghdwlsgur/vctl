#!/usr/bin/env bash
# vctl 관리자 1회 부트스트랩 — Vault 의 DB 엔진·role·정책을 구성한다.
# 전제: VAULT_ADDR 설정 + admin_mode 토큰으로 로그인됨. Postgres 는 이미 떠 있음.
set -euo pipefail

# Vault 는 in-cluster 라 k8s svc DNS 로 Postgres 에 닿는다.
PG_HOST="${PG_HOST:-vctl-postgres.vctl.svc.cluster.local}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-vctl}"
PG_ADMIN_USER="${PG_ADMIN_USER:-vctl_admin}"   # StatefulSet POSTGRES_USER(슈퍼유저) — Vault 가 동적 role 생성에 사용
PG_ADMIN_PASS="${PG_ADMIN_PASS:?PG_ADMIN_PASS 필요}"
PG_MIGRATION_OWNER="${PG_MIGRATION_OWNER:-vctl_owner}"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> 1) database 시크릿 엔진"
vault secrets enable -path=database database 2>/dev/null || echo "   (이미 활성)"

echo "==> 1.5) 마이그레이션 stable owner role"
command -v psql >/dev/null || { echo "psql 필요: ${PG_MIGRATION_OWNER} role 을 생성해야 합니다"; exit 1; }
PGPASSWORD="${PG_ADMIN_PASS}" psql "host=${PG_HOST} port=${PG_PORT} dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${PG_MIGRATION_OWNER}') THEN
    CREATE ROLE ${PG_MIGRATION_OWNER} NOLOGIN;
  END IF;
END
\$\$;
GRANT CONNECT ON DATABASE ${PG_DB} TO ${PG_MIGRATION_OWNER};
GRANT USAGE,CREATE ON SCHEMA public TO ${PG_MIGRATION_OWNER};
ALTER SCHEMA public OWNER TO ${PG_MIGRATION_OWNER};
SQL

echo "==> 2) Postgres 연결 등록 (TLS verify-full)"
vault write database/config/vctl-pg \
  plugin_name=postgresql-database-plugin \
  allowed_roles="vctl-ro,vctl-rw,vctl-migrator" \
  connection_url="postgresql://{{username}}:{{password}}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=verify-full" \
  username="${PG_ADMIN_USER}" \
  password="${PG_ADMIN_PASS}"

echo "==> 3) root 자격 즉시 로테이션 (부트스트랩 비번 폐기)"
vault write -f database/rotate-root/vctl-pg

echo "==> 4) 읽기 role (TTL 1h / max 4h)"
vault write database/roles/vctl-ro \
  db_name=vctl-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT CONNECT ON DATABASE ${PG_DB} TO \"{{name}}\"; \
GRANT USAGE ON SCHEMA public TO \"{{name}}\"; \
GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{name}}\";"

echo "==> 5) 쓰기 role (sync/admin, TTL 1h)"
vault write database/roles/vctl-rw \
  db_name=vctl-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT CONNECT ON DATABASE ${PG_DB} TO \"{{name}}\"; \
GRANT USAGE,CREATE ON SCHEMA public TO \"{{name}}\"; \
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\"; \
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO \"{{name}}\";"

echo "==> 5.5) 마이그레이션 role (stable owner 로 SET ROLE)"
vault write database/roles/vctl-migrator \
  db_name=vctl-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT ${PG_MIGRATION_OWNER} TO \"{{name}}\";"

echo "==> 6) 정책"
vault policy write vctl-user  "${DIR}/vctl-user.hcl"
vault policy write vctl-admin "${DIR}/vctl-admin.hcl"

echo "==> 7) 팀원 계정 (v1: userpass). 예시 — albert"
echo "   vault write auth/userpass/users/albert password=<once> policies=vctl-user"
echo
echo "완료. 팀원은 'vctl login' → 'vctl ssh <host>' 만 하면 됩니다."
echo "관리자: 인벤토리 최초 적재는  vctl sync --migrate  (vctl-admin 정책 토큰으로)"
