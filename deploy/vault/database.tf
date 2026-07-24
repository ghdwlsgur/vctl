# Postgres dynamic credentials.  ★그룹 롤 GRANT 모델 (2026-07-24 장애 재발 방지)
#
# Two Postgres-side prerequisites Terraform can't create (run as vctl_admin, once,
# BEFORE apply):
#   1. postgres-owner.sh   — stable owner role vctl_owner (migration object owner)
#   2. postgres-groups.sh  — shared NOLOGIN group roles (vctl_ro/rw/…) + their table
#                            privileges. Dynamic users inherit these via membership.
# Rotate the root credential after apply: vault write -f database/rotate-root/vctl-pg
#
# WHY GROUP MODEL: previously each dynamic user (v-…) received its own per-table
# GRANT; with `GRANT ... ON ALL TABLES` this piled per-user ACL entries onto
# access_log's pg_class.relacl until a GRANT overflowed the 8160-byte page limit
# (ERROR: row is too big, SQLSTATE 54000) and all RO/RW issuance failed. Granting
# table privileges to a group ONCE and giving dynamic users only group membership
# bounds relacl entries by group count, not credential count. This mirrors the
# already-healthy vctl-migrator (`GRANT vctl_owner TO …`). CONNECT/USAGE/table privs
# are inherited from the group, so no per-user GRANTs remain here.
#
# This file (vctl repo, break-glass recovery) is kept in sync with the production
# vault-iac/database.tf.
resource "vault_mount" "database" {
  path = "database"
  type = "database"
}

resource "vault_database_secret_backend_connection" "vctl_pg" {
  backend = vault_mount.database.path
  name    = "vctl-pg"
  allowed_roles = [
    "vctl-ro", "vctl-identity", "vctl-rw", "vctl-audit-ro",
    "vctl-audit-writer", "vctl-audit-ingest", "vctl-pruner",
    "vctl-status", "vctl-migrator"
  ]

  postgresql {
    connection_url = "postgresql://{{username}}:{{password}}@${var.pg_host}:${var.pg_port}/${var.pg_db}?sslmode=${var.pg_sslmode}"
    username       = var.pg_admin_user
    password       = var.pg_admin_pass
  }
}

locals {
  db_backend = vault_mount.database.path
  db_name    = vault_database_secret_backend_connection.vctl_pg.name

  # Dynamic user: LOGIN role + group membership only. CONNECT/USAGE/table privileges
  # are inherited from the group (created by postgres-groups.sh). No per-user GRANTs.
  create_login = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"

  # Robust, idempotent lease teardown for every role (also fixes the previously
  # empty revocation on audit/identity/pruner → no more orphan leak on expiry).
  revoke_stmts = [
    "REASSIGN OWNED BY \"{{name}}\" TO ${var.pg_admin_user};",
    "DROP OWNED BY \"{{name}}\";",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]
}

# ro: inventory and app-RBAC reads. Audit payloads are deliberately excluded.
resource "vault_database_secret_backend_role" "ro" {
  backend               = local.db_backend
  name                  = "vctl-ro"
  db_name               = local.db_name
  default_ttl           = 3600
  max_ttl               = 14400
  creation_statements   = ["${local.create_login} GRANT vctl_ro TO \"{{name}}\";"]
  revocation_statements = local.revoke_stmts
}

# identity: login-time seen_users upsert only.
resource "vault_database_secret_backend_role" "identity" {
  backend               = local.db_backend
  name                  = "vctl-identity"
  db_name               = local.db_name
  default_ttl           = 3600
  max_ttl               = 14400
  creation_statements   = ["${local.create_login} GRANT vctl_identity TO \"{{name}}\";"]
  revocation_statements = local.revoke_stmts
}

# rw: operator-managed inventory and app-RBAC writes only.
resource "vault_database_secret_backend_role" "rw" {
  backend               = local.db_backend
  name                  = "vctl-rw"
  db_name               = local.db_name
  default_ttl           = 3600
  max_ttl               = 14400
  creation_statements   = ["${local.create_login} GRANT vctl_rw TO \"{{name}}\";"]
  revocation_statements = local.revoke_stmts
}

# Audit readers can inspect sensitive session data but cannot modify it.
resource "vault_database_secret_backend_role" "audit_ro" {
  backend               = local.db_backend
  name                  = "vctl-audit-ro"
  db_name               = local.db_name
  default_ttl           = 3600
  max_ttl               = 14400
  creation_statements   = ["${local.create_login} GRANT vctl_audit_ro TO \"{{name}}\";"]
  revocation_statements = local.revoke_stmts
}

# SSH clients append access attempts but cannot read or alter prior records.
resource "vault_database_secret_backend_role" "audit_writer" {
  backend               = local.db_backend
  name                  = "vctl-audit-writer"
  db_name               = local.db_name
  default_ttl           = 3600
  max_ttl               = 14400
  creation_statements   = ["${local.create_login} GRANT vctl_audit_writer TO \"{{name}}\";"]
  revocation_statements = local.revoke_stmts
}

# Host collectors may append events and maintain session lifecycle, never delete.
resource "vault_database_secret_backend_role" "audit_ingest" {
  backend               = local.db_backend
  name                  = "vctl-audit-ingest"
  db_name               = local.db_name
  default_ttl           = 3600
  max_ttl               = 14400
  creation_statements   = ["${local.create_login} GRANT vctl_audit_ingest TO \"{{name}}\";"]
  revocation_statements = local.revoke_stmts
}

# Retention jobs can count and delete audit rows, but cannot rewrite them.
resource "vault_database_secret_backend_role" "pruner" {
  backend               = local.db_backend
  name                  = "vctl-pruner"
  db_name               = local.db_name
  default_ttl           = 3600
  max_ttl               = 14400
  creation_statements   = ["${local.create_login} GRANT vctl_pruner TO \"{{name}}\";"]
  revocation_statements = local.revoke_stmts
}

# status: node-agent (servers read, server_status upsert)
resource "vault_database_secret_backend_role" "status" {
  backend               = local.db_backend
  name                  = "vctl-status"
  db_name               = local.db_name
  default_ttl           = 3600
  max_ttl               = 14400
  creation_statements   = ["${local.create_login} GRANT vctl_status TO \"{{name}}\";"]
  revocation_statements = local.revoke_stmts
}

# migrator: SET ROLE to the stable owner for schema changes. Unchanged — already a
# group-membership model (never did per-user table GRANTs), so it was unaffected.
resource "vault_database_secret_backend_role" "migrator" {
  backend     = local.db_backend
  name        = "vctl-migrator"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT ${var.pg_migration_owner} TO \"{{name}}\";",
  ]
  revocation_statements = local.revoke_stmts
}
