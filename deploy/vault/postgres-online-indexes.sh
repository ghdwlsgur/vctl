#!/usr/bin/env bash
# Apply vctl's online indexes without blocking writes for the duration of a
# migration transaction. Idempotent; safe to resume after interruption.
set -euo pipefail

PG_DB="${PG_DB:-vctl}"
PG_ADMIN_USER="${PG_ADMIN_USER:-vctl_admin}"
PG_ADMIN_PASS="${PG_ADMIN_PASS:?PG_ADMIN_PASS is required}"
PG_HOST="${PG_HOST:-vctl-postgres.vctl.svc.cluster.local}"
PG_PORT="${PG_PORT:-5432}"
# `-` rather than `:-`: an explicit PG_EXEC_POD="" selects direct psql.
PG_EXEC_POD="${PG_EXEC_POD-vctl-postgres-0}"
PG_EXEC_NS="${PG_EXEC_NS:-vctl}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INDEX_SQL="${SCRIPT_DIR}/postgres-online-indexes.sql"

if [ -n "${PG_EXEC_POD}" ]; then
  kubectl exec -i -n "${PG_EXEC_NS}" "${PG_EXEC_POD}" -- \
    env PGPASSWORD="${PG_ADMIN_PASS}" psql -h 127.0.0.1 -U "${PG_ADMIN_USER}" \
      -d "${PG_DB}" -v ON_ERROR_STOP=1 < "${INDEX_SQL}"
else
  command -v psql >/dev/null || { echo "psql is required"; exit 1; }
  PGPASSWORD="${PG_ADMIN_PASS}" psql \
    "host=${PG_HOST} port=${PG_PORT} dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require" \
    -v ON_ERROR_STOP=1 < "${INDEX_SQL}"
fi

echo "vctl online indexes are present."
