#!/usr/bin/env bash
# Create the stable Postgres role that OWNS vctl's migration objects (vctl_owner).
# This is Postgres-side DDL the Vault Terraform provider can't do, so it's the one
# step that stays shell. Run it ONCE *before* `terraform apply` — the vctl-migrator
# DB role SET ROLEs to this owner so migrations get stable object ownership.
#
#   PG_ADMIN_PASS=<root-pw> ./postgres-owner.sh
set -euo pipefail

PG_DB="${PG_DB:-vctl}"
PG_ADMIN_USER="${PG_ADMIN_USER:-vctl_admin}"
PG_ADMIN_PASS="${PG_ADMIN_PASS:?PG_ADMIN_PASS is required}"
PG_MIGRATION_OWNER="${PG_MIGRATION_OWNER:-vctl_owner}"
PG_HOST="${PG_HOST:-vctl-postgres.vctl.svc.cluster.local}"
PG_PORT="${PG_PORT:-5432}"
# In the k8s deployment psql runs inside the pod (laptop need not reach svc DNS).
# For direct psql (legacy/bare-metal), set PG_EXEC_POD="".
PG_EXEC_POD="${PG_EXEC_POD:-vctl-postgres-0}"
PG_EXEC_NS="${PG_EXEC_NS:-vctl}"

OWNER_SQL="DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${PG_MIGRATION_OWNER}') THEN CREATE ROLE ${PG_MIGRATION_OWNER} NOLOGIN; END IF; END \$\$; GRANT CONNECT ON DATABASE ${PG_DB} TO ${PG_MIGRATION_OWNER}; GRANT USAGE,CREATE ON SCHEMA public TO ${PG_MIGRATION_OWNER}; ALTER SCHEMA public OWNER TO ${PG_MIGRATION_OWNER};"

if [ -n "${PG_EXEC_POD}" ]; then
  kubectl exec -n "${PG_EXEC_NS}" "${PG_EXEC_POD}" -- \
    env PGPASSWORD="${PG_ADMIN_PASS}" psql -h 127.0.0.1 -U "${PG_ADMIN_USER}" -d "${PG_DB}" -v ON_ERROR_STOP=1 -c "${OWNER_SQL}"
else
  command -v psql >/dev/null || { echo "psql is required"; exit 1; }
  PGPASSWORD="${PG_ADMIN_PASS}" psql "host=${PG_HOST} port=${PG_PORT} dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require" -v ON_ERROR_STOP=1 -c "${OWNER_SQL}"
fi

echo "owner role '${PG_MIGRATION_OWNER}' ensured. Next: terraform apply."
