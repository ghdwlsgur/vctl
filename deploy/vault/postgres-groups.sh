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
PG_KUBE_CONTEXT="${PG_KUBE_CONTEXT:-}"

# Group -> privileges. Mirrors the per-user grants that database.tf USED to embed,
# now applied to shared groups exactly once. Keep in sync with database.tf grants.
#
# THIS FILE IS NOT THE WHOLE GRANT PICTURE. vctl migrations also grant, for the
# tables they themselves create (grep GRANT in vctl internal/store/migrations/):
#   012  wg_endpoint_annotations              -> vctl_ro(R), vctl_rw(RW)
#   015  server_capabilities                  -> vctl_ro(R), vctl_status(RW), vctl_rw(RW)
#        + openstack_deployments/memberships  -> vctl_ro(R)
#   017  openstack_instances(+addresses)      -> vctl_ro(R), vctl_rw(RW)
#   018  openstack_reconcile_runs/control_hosts -> vctl_ro(R), vctl_rw(RW)
#   023  access_log                           -> vctl_pruner(SELECT,DELETE)
#   024  openstack_instances                  -> vctl_openstack_pruner(SELECT,DELETE)
#   025  ALL TABLES/SEQUENCES (+defaults)     -> vctl_backup(R)
# Auditing "what can role X reach" means reading BOTH places. Ownership rule of
# thumb: a migration grants on tables it creates; this script owns bootstrap
# (role creation), blankets (sequences, backup), and additions to tables that
# already existed (e.g. vctl_status's openstack topology reads for the MOTD).
read -r -d '' GROUPS_SQL <<'SQL' || true
DO $$
DECLARE g text;
BEGIN
  FOREACH g IN ARRAY ARRAY[
    'vctl_ro','vctl_rw','vctl_status','vctl_identity',
    'vctl_audit_ro','vctl_audit_writer','vctl_audit_ingest','vctl_pruner',
    'vctl_openstack_pruner','vctl_backup','vctl_reconcile'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = g) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN', g);
    END IF;
  END LOOP;
END $$;

-- CONNECT + schema USAGE for every group (inherited by dynamic members).
GRANT CONNECT ON DATABASE vctl TO
  vctl_ro, vctl_rw, vctl_status, vctl_identity,
  vctl_audit_ro, vctl_audit_writer, vctl_audit_ingest, vctl_pruner,
  vctl_openstack_pruner, vctl_backup, vctl_reconcile;
GRANT USAGE ON SCHEMA public TO
  vctl_ro, vctl_rw, vctl_status, vctl_identity,
  vctl_audit_ro, vctl_audit_writer, vctl_audit_ingest, vctl_pruner,
  vctl_openstack_pruner, vctl_backup, vctl_reconcile;

-- ro: inventory + app-RBAC + IPAM/WireGuard reads. Audit payloads deliberately excluded.
GRANT SELECT ON servers, server_status, rbac_groups, rbac_members, rbac_grants, seen_users,
  ip_allocations, wg_interfaces, wg_peers, wg_peer_status TO vctl_ro;

-- rw: operator-managed inventory + app-RBAC + IPAM/WireGuard writes.
GRANT SELECT,INSERT,UPDATE,DELETE ON servers, server_status, rbac_groups, rbac_members, rbac_grants, seen_users,
  ip_allocations, wg_interfaces, wg_peers, wg_peer_status TO vctl_rw;

-- status: node-agent — servers read, server_status upsert.
GRANT SELECT ON servers TO vctl_status;
GRANT SELECT,INSERT,UPDATE ON server_status TO vctl_status;
-- MOTD 렌더용 팜 토폴로지 읽기 (vctl PR #235). 함대의 모든 호스트가 전 팜의
-- 토폴로지(비밀 아님·행 단위 축소는 호스트별 롤이 필요해 과함)를 읽게 된다는
-- 트레이드오프를 알고 넣은 것. 이 grant 의 명세는 nodeagent.Sink 인터페이스다.
GRANT SELECT ON openstack_deployments, openstack_memberships, openstack_control_hosts TO vctl_status;

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
GRANT SELECT,DELETE ON access_log, audit_session, kernel_event TO vctl_pruner;

-- reconcile: 팜 컨트롤러의 reconciler / 클러스터 CronJob — reconcile 이 쓰는
-- 표면만. vctl_rw 를 주면 컨트롤러의 root 가 운영자 쓰기 표면 전체(servers·
-- rbac·ipam·wg)를 갖는다 — rbac_grants 자가 부여와 jump_via 변조까지. 이
-- 그룹은 membership 확정·run 기록·control host·VM 스냅샷에 닿고, 그 판단에
-- 필요한 인벤토리 읽기(servers, server_capabilities)만 얹는다.
GRANT SELECT ON servers, server_capabilities TO vctl_reconcile;
GRANT SELECT,INSERT,UPDATE ON openstack_deployments, openstack_reconcile_runs,
  openstack_instances TO vctl_reconcile;
GRANT SELECT,INSERT,UPDATE,DELETE ON openstack_memberships, openstack_control_hosts,
  openstack_instance_addresses TO vctl_reconcile;

-- OpenStack history pruner: deleted-instance records only. Address rows cascade.
GRANT SELECT,DELETE ON openstack_instances TO vctl_openstack_pruner;

-- Backup: logical dump reads every current and future table/sequence, no writes.
GRANT SELECT ON ALL TABLES IN SCHEMA public TO vctl_backup;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO vctl_backup;

-- Sequences: every write group needs USAGE on the serial PKs it inserts through
-- (first surfaced 2026-07-25: rw upsert of a NEW server hit servers_id_seq 42501).
-- Blanket-grant current sequences and default-privilege future ones so new
-- migrations don't reintroduce the gap.
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO
  vctl_rw, vctl_status, vctl_identity, vctl_audit_writer, vctl_audit_ingest,
  vctl_reconcile;
ALTER DEFAULT PRIVILEGES FOR ROLE vctl_owner IN SCHEMA public
  GRANT USAGE,SELECT ON SEQUENCES TO
  vctl_rw, vctl_status, vctl_identity, vctl_audit_writer, vctl_audit_ingest,
  vctl_reconcile;
ALTER DEFAULT PRIVILEGES FOR ROLE vctl_owner IN SCHEMA public
  GRANT SELECT ON TABLES TO vctl_backup;
ALTER DEFAULT PRIVILEGES FOR ROLE vctl_owner IN SCHEMA public
  GRANT SELECT ON SEQUENCES TO vctl_backup;
SQL

if [ -n "${PG_EXEC_POD}" ]; then
  KUBECTL=(kubectl)
  if [ -n "${PG_KUBE_CONTEXT}" ]; then
    KUBECTL+=(--context "${PG_KUBE_CONTEXT}")
  fi
  "${KUBECTL[@]}" exec -i -n "${PG_EXEC_NS}" "${PG_EXEC_POD}" -- \
    env PGPASSWORD="${PG_ADMIN_PASS}" psql -h 127.0.0.1 -U "${PG_ADMIN_USER}" -d "${PG_DB}" -v ON_ERROR_STOP=1 <<SQL
${GROUPS_SQL}
SQL
else
  command -v psql >/dev/null || { echo "psql is required"; exit 1; }
  PGPASSWORD="${PG_ADMIN_PASS}" psql "host=${PG_HOST} port=${PG_PORT} dbname=${PG_DB} user=${PG_ADMIN_USER} sslmode=require" -v ON_ERROR_STOP=1 <<SQL
${GROUPS_SQL}
SQL
fi

echo "group roles ensured (vctl_ro/rw/status/identity/audit_ro/audit_writer/audit_ingest/pruner/openstack_pruner/backup/reconcile)."
echo "Next: terraform apply (group-model database.tf). Any legacy v-% orphan cleanup: see the incident runbook."
