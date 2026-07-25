#!/usr/bin/env bash
# Bootstrap the shared NOLOGIN GROUP roles that vctl's dynamic DB users inherit.
#
# WHY: previously each Vault dynamic user (v-…) got its own per-table GRANT. With
# `GRANT ... ON ALL TABLES` on the drifted ro/rw roles this piled per-user ACL
# entries onto access_log's pg_class.relacl until a GRANT overflowed the 8160-byte
# page limit (ERROR: row is too big, SQLSTATE 54000) and all RO/RW issuance failed.
# Fix: grant table privileges to a group ONCE; dynamic users only get group
# membership (see database.tf `GRANT <group> TO "{{name}}"`), so relacl entry count
# is bounded by the number of groups, not the number of issued credentials.
#
# This is Postgres-side DDL the Vault Terraform provider can't do (same rationale
# as postgres-owner.sh), and it MUST run as a superuser: vctl_owner has no
# CREATEROLE (verified 2026-07-24), so migrations (which SET ROLE vctl_owner)
# cannot create these. Run it as vctl_admin.
#
# Idempotent: safe to re-run. Run it ONCE before the group-model `terraform apply`.
#
#   PG_ADMIN_PASS=<root-pw> ./postgres-groups.sh
set -euo pipefail

PG_DB="${PG_DB:-vctl}"
PG_ADMIN_USER="${PG_ADMIN_USER:-vctl_admin}"
PG_ADMIN_PASS="${PG_ADMIN_PASS:?PG_ADMIN_PASS is required}"
PG_HOST="${PG_HOST:-vctl-postgres.vctl.svc.cluster.local}"
PG_PORT="${PG_PORT:-5432}"
# In the k8s deployment psql runs inside the pod (laptop need not reach svc DNS).
# For direct psql (bare-metal / laptop via vctl-postgres.sre.local), set PG_EXEC_POD="".
PG_EXEC_POD="${PG_EXEC_POD:-vctl-postgres-0}"
PG_EXEC_NS="${PG_EXEC_NS:-vctl}"

# Group -> privileges. Mirrors the per-user grants that database.tf USED to embed,
# now applied to shared groups exactly once. Keep in sync with database.tf grants.
read -r -d '' GROUPS_SQL <<'SQL' || true
DO $$
DECLARE g text;
BEGIN
  FOREACH g IN ARRAY ARRAY[
    'vctl_ro','vctl_rw','vctl_status','vctl_identity',
    'vctl_audit_ro','vctl_audit_writer','vctl_audit_ingest','vctl_pruner'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = g) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN', g);
    END IF;
  END LOOP;
END $$;

-- CONNECT + schema USAGE for every group (inherited by dynamic members).
GRANT CONNECT ON DATABASE vctl TO
  vctl_ro, vctl_rw, vctl_status, vctl_identity,
  vctl_audit_ro, vctl_audit_writer, vctl_audit_ingest, vctl_pruner;
GRANT USAGE ON SCHEMA public TO
  vctl_ro, vctl_rw, vctl_status, vctl_identity,
  vctl_audit_ro, vctl_audit_writer, vctl_audit_ingest, vctl_pruner;

-- ro: inventory + app-RBAC + IPAM/WireGuard reads. Audit payloads deliberately excluded.
GRANT SELECT ON servers, server_status, rbac_groups, rbac_members, rbac_grants, seen_users,
  ip_allocations, wg_interfaces, wg_peers, wg_peer_status TO vctl_ro;

-- rw: operator-managed inventory + app-RBAC + IPAM/WireGuard writes.
GRANT SELECT,INSERT,UPDATE,DELETE ON servers, server_status, rbac_groups, rbac_members, rbac_grants, seen_users,
  ip_allocations, wg_interfaces, wg_peers, wg_peer_status TO vctl_rw;

-- status: node-agent — servers read, server_status upsert.
GRANT SELECT ON servers TO vctl_status;
GRANT SELECT,INSERT,UPDATE ON server_status TO vctl_status;

-- identity: login-time seen_users upsert only.
GRANT SELECT,INSERT,UPDATE ON seen_users TO vctl_identity;

-- audit-ro: read sensitive session/audit data, no writes.
GRANT SELECT ON access_log, audit_session, kernel_event TO vctl_audit_ro;

-- audit-writer: append access attempts only.
GRANT INSERT ON access_log TO vctl_audit_writer;
GRANT USAGE,SELECT ON SEQUENCE access_log_id_seq TO vctl_audit_writer;

-- audit-ingest: host collectors append events + maintain session lifecycle, never delete.
GRANT SELECT,INSERT,UPDATE ON audit_session TO vctl_audit_ingest;
GRANT SELECT,INSERT ON kernel_event TO vctl_audit_ingest;
GRANT USAGE,SELECT ON SEQUENCE audit_session_id_seq, kernel_event_id_seq TO vctl_audit_ingest;

-- pruner: retention — count/delete audit rows, no rewrite.
GRANT SELECT,DELETE ON audit_session, kernel_event TO vctl_pruner;

-- Sequences: every write group needs USAGE on the serial PKs it inserts through
-- (first surfaced 2026-07-25: rw upsert of a NEW server hit servers_id_seq 42501).
-- Blanket-grant current sequences and default-privilege future ones so new
-- migrations don't reintroduce the gap.
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO
  vctl_rw, vctl_status, vctl_identity, vctl_audit_writer, vctl_audit_ingest;
ALTER DEFAULT PRIVILEGES FOR ROLE vctl_owner IN SCHEMA public
  GRANT USAGE,SELECT ON SEQUENCES TO
  vctl_rw, vctl_status, vctl_identity, vctl_audit_writer, vctl_audit_ingest;
SQL

if [ -n "${PG_EXEC_POD}" ]; then
  kubectl exec -i -n "${PG_EXEC_NS}" "${PG_EXEC_POD}" -- \
    env PGPASSWORD="${PG_ADMIN_PASS}" psql -h 127.0.0.1 -U "${PG_ADMIN_USER}" -d "${PG_DB}" -v ON_ERROR_STOP=1 <<SQL
${GROUPS_SQL}
SQL
else
  command -v psql >/dev/null || { echo "psql is required"; exit 1; }
  PGPASSWORD="${PG_ADMIN_PASS}" psql "host=${PG_HOST} port=${PG_PORT} dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require" -v ON_ERROR_STOP=1 <<SQL
${GROUPS_SQL}
SQL
fi

echo "group roles ensured (vctl_ro/rw/status/identity/audit_ro/audit_writer/audit_ingest/pruner)."
echo "Next: terraform apply (group-model database.tf). Any legacy v-% orphan cleanup: see the incident runbook."
