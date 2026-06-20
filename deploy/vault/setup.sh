#!/usr/bin/env bash
# One-time vctl admin bootstrap for Vault DB engine, roles, and policies.
# Prerequisites: VAULT_ADDR is set, the current Vault token has admin access,
# and Postgres is already running.
set -euo pipefail

# Vault reaches Postgres through the in-cluster Kubernetes service DNS name.
PG_HOST="${PG_HOST:-vctl-postgres.vctl.svc.cluster.local}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-vctl}"
PG_ADMIN_USER="${PG_ADMIN_USER:-vctl_admin}"   # StatefulSet POSTGRES_USER used by Vault for dynamic role creation.
PG_ADMIN_PASS="${PG_ADMIN_PASS:?PG_ADMIN_PASS is required}"
PG_MIGRATION_OWNER="${PG_MIGRATION_OWNER:-vctl_owner}"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> 1) database secrets engine"
vault secrets enable -path=database database 2>/dev/null || echo "   (already enabled)"

echo "==> 1.5) stable migration owner role"
command -v psql >/dev/null || { echo "psql is required to create role ${PG_MIGRATION_OWNER}"; exit 1; }
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

echo "==> 2) Postgres connection registration (TLS verify-full)"
vault write database/config/vctl-pg \
  plugin_name=postgresql-database-plugin \
  allowed_roles="vctl-ro,vctl-rw,vctl-migrator" \
  connection_url="postgresql://{{username}}:{{password}}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=verify-full" \
  username="${PG_ADMIN_USER}" \
  password="${PG_ADMIN_PASS}"

echo "==> 3) root credential rotation"
vault write -f database/rotate-root/vctl-pg

echo "==> 4) read role (TTL 1h / max 4h)"
vault write database/roles/vctl-ro \
  db_name=vctl-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT CONNECT ON DATABASE ${PG_DB} TO \"{{name}}\"; \
GRANT USAGE ON SCHEMA public TO \"{{name}}\"; \
GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{name}}\";"

echo "==> 5) write role (sync/admin, TTL 1h)"
vault write database/roles/vctl-rw \
  db_name=vctl-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT CONNECT ON DATABASE ${PG_DB} TO \"{{name}}\"; \
GRANT USAGE,CREATE ON SCHEMA public TO \"{{name}}\"; \
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; \
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\"; \
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO \"{{name}}\";"

echo "==> 5.5) migration role (SET ROLE to stable owner)"
vault write database/roles/vctl-migrator \
  db_name=vctl-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT ${PG_MIGRATION_OWNER} TO \"{{name}}\";"

echo "==> 6) policies"
vault policy write vctl-user  "${DIR}/vctl-user.hcl"
vault policy write vctl-admin "${DIR}/vctl-admin.hcl"

echo "==> 7) userpass account example"
echo "   vault write auth/userpass/users/albert password=<once> policies=vctl-user"
echo
echo "Done. Users can run: vctl login; vctl ssh <host>"
echo "Initial inventory load: vctl sync --migrate with a vctl-admin token"
