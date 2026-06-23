#!/usr/bin/env bash
# Complete vctl Vault bootstrap / break-glass recovery — every Vault object vctl
# depends on, in one idempotent script. See README.md for the dependency map.
#
# Prerequisites: VAULT_ADDR set, current token has admin rights, Postgres running.
# vault-iac (Terraform) is the IaC source of truth; this is the self-contained
# equivalent so the stack can be rebuilt from the vctl repo alone.
set -euo pipefail

# Vault reaches Postgres through the in-cluster Kubernetes service DNS name.
PG_HOST="${PG_HOST:-vctl-postgres.vctl.svc.cluster.local}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-vctl}"
PG_ADMIN_USER="${PG_ADMIN_USER:-vctl_admin}"   # POSTGRES_USER Vault uses to create dynamic roles.
PG_ADMIN_PASS="${PG_ADMIN_PASS:?PG_ADMIN_PASS is required}"
PG_MIGRATION_OWNER="${PG_MIGRATION_OWNER:-vctl_owner}"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Public SRE root CA (for OIDC discovery TLS to gitlab.sre.local). Single copy:
# the one embedded in the vctl binary. Override with SRE_CA=/path if needed.
SRE_CA="${SRE_CA:-${DIR}/../../internal/config/innogrid-sre-root-ca.crt}"

echo "==> 1) database secrets engine"
vault secrets enable -path=database database 2>/dev/null || echo "   (already enabled)"

echo "==> 1.5) stable migration owner role"
# In the k8s deployment, psql runs inside the pod, so the laptop need not reach
# the service DNS. For direct psql (legacy/bare-metal), set PG_EXEC_POD="".
PG_EXEC_POD="${PG_EXEC_POD:-vctl-postgres-0}"
PG_EXEC_NS="${PG_EXEC_NS:-vctl}"
OWNER_SQL="DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${PG_MIGRATION_OWNER}') THEN CREATE ROLE ${PG_MIGRATION_OWNER} NOLOGIN; END IF; END \$\$; GRANT CONNECT ON DATABASE ${PG_DB} TO ${PG_MIGRATION_OWNER}; GRANT USAGE,CREATE ON SCHEMA public TO ${PG_MIGRATION_OWNER}; ALTER SCHEMA public OWNER TO ${PG_MIGRATION_OWNER};"
if [ -n "${PG_EXEC_POD}" ]; then
  kubectl exec -n "${PG_EXEC_NS}" "${PG_EXEC_POD}" -- \
    env PGPASSWORD="${PG_ADMIN_PASS}" psql -h 127.0.0.1 -U "${PG_ADMIN_USER}" -d "${PG_DB}" -v ON_ERROR_STOP=1 -c "${OWNER_SQL}"
else
  command -v psql >/dev/null || { echo "psql is required to create role ${PG_MIGRATION_OWNER}"; exit 1; }
  PGPASSWORD="${PG_ADMIN_PASS}" psql "host=${PG_HOST} port=${PG_PORT} dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require" -v ON_ERROR_STOP=1 -c "${OWNER_SQL}"
fi

echo "==> 2) Postgres connection registration (TLS verify-full)"
vault write database/config/vctl-pg \
  plugin_name=postgresql-database-plugin \
  allowed_roles="vctl-ro,vctl-rw,vctl-status,vctl-migrator" \
  connection_url="postgresql://{{username}}:{{password}}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=${PG_SSLMODE:-verify-full}" \
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

echo "==> 5.5) node status role (TTL 1h)"
vault write database/roles/vctl-status \
  db_name=vctl-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT CONNECT ON DATABASE ${PG_DB} TO \"{{name}}\"; \
GRANT USAGE ON SCHEMA public TO \"{{name}}\"; \
GRANT SELECT ON servers TO \"{{name}}\"; \
GRANT SELECT,INSERT,UPDATE ON server_status TO \"{{name}}\";"

echo "==> 5.6) migration role (SET ROLE to stable owner)"
vault write database/roles/vctl-migrator \
  db_name=vctl-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
GRANT ${PG_MIGRATION_OWNER} TO \"{{name}}\";"

echo "==> 6) policies (least privilege)"
for p in vctl-user vctl-admin vctl-node vctl-collector vctl-host; do
  vault policy write "$p" "${DIR}/${p}.hcl"
done

echo "==> 7) SSH CA (sign per-connection certs for 'vctl ssh')"
# generate_signing_key mints a NEW CA keypair on a fresh mount. WARNING: on an
# existing system, recreating this rotates the CA and every host's
# TrustedUserCAKeys must be re-onboarded (vctl trust-ca). Skips if already set.
vault secrets enable -path=ssh ssh 2>/dev/null || echo "   (ssh mount already enabled)"
vault write ssh/config/ca generate_signing_key=true 2>/dev/null || echo "   (CA key already configured — left intact)"
vault write ssh/roles/sre-core key_type=ca allow_user_certificates=true \
  allowed_users="ubuntu,rocky,root" default_user=ubuntu \
  allowed_extensions="permit-pty,permit-port-forwarding,permit-agent-forwarding,permit-X11-forwarding,permit-user-rc" \
  default_extensions=permit-pty="" ttl=1800 max_ttl=7200

echo "==> 8) AppRoles (periodic tokens; secret_ids minted per host/workstation at use)"
vault auth enable approle 2>/dev/null || echo "   (approle already enabled)"
# vctl-collector: host audit daemons -> vctl-rw.
vault write auth/approle/role/vctl-collector token_policies=vctl-collector \
  token_ttl=3600 token_max_ttl=0 token_period=86400 token_type=service \
  secret_id_ttl=2592000 secret_id_num_uses=0
# vctl-host: full host stack (collector+watch+node-agent) -> vctl-rw + vctl-status.
vault write auth/approle/role/vctl-host token_policies=vctl-host \
  token_ttl=3600 token_max_ttl=0 token_period=86400 token_type=service \
  secret_id_ttl=2592000 secret_id_num_uses=0
# vctl-user: optional workstation auto-auth (shared identity — humans use OIDC).
vault write auth/approle/role/vctl-user token_policies=vctl-user \
  token_ttl=3600 token_max_ttl=0 token_period=86400 token_type=service \
  secret_id_ttl=0 secret_id_num_uses=0

echo "==> 9) OIDC auth — per-person GitLab SSO ('vctl login')"
# Needs the client_id/secret seed at kv/services/vault-oidc-gitlab (created by
# the gitlab-structure IaC, or seeded manually). Skips with a notice if absent.
if vault kv get -field=client_id kv/services/vault-oidc-gitlab >/dev/null 2>&1; then
  OIDC_CID="$(vault kv get -field=client_id kv/services/vault-oidc-gitlab)"
  OIDC_CSEC="$(vault kv get -field=client_secret kv/services/vault-oidc-gitlab)"
  vault auth enable -path=oidc oidc 2>/dev/null || echo "   (oidc already enabled)"
  vault write auth/oidc/config \
    oidc_discovery_url="https://gitlab.sre.local" \
    oidc_discovery_ca_pem=@"${SRE_CA}" \
    oidc_client_id="${OIDC_CID}" oidc_client_secret="${OIDC_CSEC}" \
    default_role="vctl"
  vault write auth/oidc/role/vctl - <<'JSON'
{ "role_type":"oidc","user_claim":"preferred_username",
  "oidc_scopes":["openid","profile","email"],"groups_claim":"groups_direct",
  "claim_mappings":{"preferred_username":"username","email":"email"},
  "allowed_redirect_uris":["http://localhost:8250/oidc/callback",
    "https://vault.sre.local/ui/vault/auth/oidc/oidc/callback"],
  "token_policies":["vctl-user"],"token_ttl":3600,"token_max_ttl":28800 }
JSON
  # NOTE: the OIDC role grants vctl-user — enough to USE vctl (login/ssh/audit,
  # and sync --migrate via vctl-migrator). The org-wide "sre group -> sre-admin"
  # elevation is a production/admin concern and lives in vault-iac, not here.
else
  echo "   (kv/services/vault-oidc-gitlab not seeded — skipping OIDC; seed then re-run)"
fi

echo "==> 10) userpass auth (bootstrap fallback — usable before the OIDC seed exists)"
vault auth enable userpass 2>/dev/null || echo "   (userpass already enabled)"
echo "   create a person: vault write auth/userpass/users/<id> password=<once> policies=vctl-user"
echo "   then: vctl login --method userpass"
echo
echo "Done. Per-person login: vctl login (GitLab SSO); connect: vctl ssh <host>."
echo "Initial inventory load: vctl sync --migrate with a vctl-admin token."
