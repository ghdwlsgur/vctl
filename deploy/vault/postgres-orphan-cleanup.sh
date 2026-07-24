#!/usr/bin/env bash
# Drop leftover `v-%` dynamic Postgres roles that Vault no longer tracks, to fully
# reset access_log's bloated pg_class.relacl after the 2026-07-24 incident.
#
# BACKGROUND: 2,4xx dynamic users accumulated, each with a direct per-user GRANT on
# access_log, pushing relacl to ~7,982B / 2,434 entries (page limit 8,160B). The
# supervisor's `vault lease revoke -prefix` only freed a little headroom; the bulk
# of orphan roles (and their ACL entries) remain because several roles had empty
# revocation_statements and the leases were untracked. DROP OWNED BY removes each
# role's ACL entries (shrinking relacl); DROP ROLE removes the role.
#
# SAFETY / CONTRACT:
#   * Run this ONLY AFTER: (1) postgres-groups.sh, (2) group-model `terraform apply`,
#     (3) `vault lease revoke -prefix database/creds/<role>` for EVERY vctl-* role.
#     After (3), any surviving v-% role is a Vault-untracked orphan.
#   * Never touches group roles (vctl_ro/…), vctl_owner, vctl_admin — only `v-%`.
#   * Skips any v-% role with a LIVE backend in pg_stat_activity (in-use → not dropped).
#   * Idempotent: re-run drops whatever remains; DROP ROLE IF EXISTS no-ops if gone.
#   * DRY-RUN by default. Actually drops only with CONFIRM=yes.
#
#   PG_ADMIN_PASS=<root-pw> ./postgres-orphan-cleanup.sh              # dry-run (counts + sample)
#   PG_ADMIN_PASS=<root-pw> CONFIRM=yes ./postgres-orphan-cleanup.sh  # execute
set -euo pipefail

PG_DB="${PG_DB:-vctl}"
PG_ADMIN_USER="${PG_ADMIN_USER:-vctl_admin}"
PG_ADMIN_PASS="${PG_ADMIN_PASS:?PG_ADMIN_PASS is required}"
PG_HOST="${PG_HOST:-vctl-postgres.vctl.svc.cluster.local}"
PG_PORT="${PG_PORT:-5432}"
PG_EXEC_POD="${PG_EXEC_POD:-vctl-postgres-0}"
PG_EXEC_NS="${PG_EXEC_NS:-vctl}"
CONFIRM="${CONFIRM:-no}"

# Target set: v-% roles that are NOT currently connected. Reused by both modes.
TARGET_CTE="WITH targets AS (
  SELECT r.rolname
  FROM pg_roles r
  WHERE r.rolname LIKE 'v-%'
    AND r.rolname NOT IN (
      SELECT usename FROM pg_stat_activity WHERE usename IS NOT NULL
    )
)"

DRYRUN_SQL="${TARGET_CTE}
SELECT
  (SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v-%')            AS v_roles_total,
  (SELECT count(*) FROM targets)                                     AS orphans_to_drop,
  (SELECT count(*) FROM pg_roles WHERE rolname LIKE 'v-%')
    - (SELECT count(*) FROM targets)                                 AS skipped_in_use;
${TARGET_CTE}
SELECT rolname FROM targets ORDER BY rolname LIMIT 20;
-- relacl before (watch access_log shrink after execute)
SELECT c.relname, pg_column_size(c.relacl) AS relacl_bytes,
       coalesce(array_length(c.relacl,1),0) AS relacl_entries
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname='access_log';"

EXEC_SQL="DO \$do\$
DECLARE t record; n int := 0;
BEGIN
  FOR t IN
    SELECT r.rolname FROM pg_roles r
    WHERE r.rolname LIKE 'v-%'
      AND r.rolname NOT IN (SELECT usename FROM pg_stat_activity WHERE usename IS NOT NULL)
  LOOP
    EXECUTE format('REASSIGN OWNED BY %I TO ${PG_ADMIN_USER}', t.rolname);
    EXECUTE format('DROP OWNED BY %I', t.rolname);
    EXECUTE format('DROP ROLE IF EXISTS %I', t.rolname);
    n := n + 1;
  END LOOP;
  RAISE NOTICE 'dropped % orphan v-%% roles', n;
END \$do\$;
-- relacl after
SELECT c.relname, pg_column_size(c.relacl) AS relacl_bytes,
       coalesce(array_length(c.relacl,1),0) AS relacl_entries
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname='access_log';"

if [ "${CONFIRM}" = "yes" ]; then
  echo ">>> EXECUTE: dropping Vault-untracked v-% orphan roles"
  SQL="${EXEC_SQL}"
else
  echo ">>> DRY-RUN (set CONFIRM=yes to drop). Counts + sample + current access_log relacl:"
  SQL="${DRYRUN_SQL}"
fi

if [ -n "${PG_EXEC_POD}" ]; then
  kubectl exec -i -n "${PG_EXEC_NS}" "${PG_EXEC_POD}" -- \
    env PGPASSWORD="${PG_ADMIN_PASS}" psql -h 127.0.0.1 -U "${PG_ADMIN_USER}" -d "${PG_DB}" -v ON_ERROR_STOP=1 <<SQL
${SQL}
SQL
else
  command -v psql >/dev/null || { echo "psql is required"; exit 1; }
  PGPASSWORD="${PG_ADMIN_PASS}" psql "host=${PG_HOST} port=${PG_PORT} dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require" -v ON_ERROR_STOP=1 <<SQL
${SQL}
SQL
fi
