# Postgres dynamic credentials. The stable owner role (var.pg_migration_owner)
# is a Postgres-side object Terraform can't create cleanly — run postgres-owner.sh
# first. Rotate the root credential after apply: vault write -f database/rotate-root/vctl-pg
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
  db_backend   = vault_mount.database.path
  db_name      = vault_database_secret_backend_connection.vctl_pg.name
  create_login = "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT CONNECT ON DATABASE ${var.pg_db} TO \"{{name}}\";"
}

# ro: inventory and app-RBAC reads. Audit payloads are deliberately excluded.
resource "vault_database_secret_backend_role" "ro" {
  backend     = local.db_backend
  name        = "vctl-ro"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT ON servers, server_status, rbac_groups, rbac_members, rbac_grants, seen_users TO \"{{name}}\";",
  ]
}

# identity: login-time seen_users upsert only.
resource "vault_database_secret_backend_role" "identity" {
  backend     = local.db_backend
  name        = "vctl-identity"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT,INSERT,UPDATE ON seen_users TO \"{{name}}\";",
  ]
}

# rw: operator-managed inventory and app-RBAC writes only.
resource "vault_database_secret_backend_role" "rw" {
  backend     = local.db_backend
  name        = "vctl-rw"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT,INSERT,UPDATE,DELETE ON servers, server_status, rbac_groups, rbac_members, rbac_grants, seen_users TO \"{{name}}\";",
  ]
}

# Audit readers can inspect sensitive session data but cannot modify it.
resource "vault_database_secret_backend_role" "audit_ro" {
  backend     = local.db_backend
  name        = "vctl-audit-ro"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT ON access_log, audit_session, kernel_event TO \"{{name}}\";",
  ]
}

# SSH clients append access attempts but cannot read or alter prior records.
resource "vault_database_secret_backend_role" "audit_writer" {
  backend     = local.db_backend
  name        = "vctl-audit-writer"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT INSERT ON access_log TO \"{{name}}\"; GRANT USAGE,SELECT ON SEQUENCE access_log_id_seq TO \"{{name}}\";",
  ]
}

# Host collectors may append events and maintain session lifecycle, never delete.
resource "vault_database_secret_backend_role" "audit_ingest" {
  backend     = local.db_backend
  name        = "vctl-audit-ingest"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT,INSERT,UPDATE ON audit_session TO \"{{name}}\"; GRANT SELECT,INSERT ON kernel_event TO \"{{name}}\"; GRANT USAGE,SELECT ON SEQUENCES audit_session_id_seq, kernel_event_id_seq TO \"{{name}}\";",
  ]
}

# Retention jobs can count and delete audit rows, but cannot rewrite them.
resource "vault_database_secret_backend_role" "pruner" {
  backend     = local.db_backend
  name        = "vctl-pruner"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT,DELETE ON audit_session, kernel_event TO \"{{name}}\";",
  ]
}

# status: node-agent (servers read, server_status upsert)
resource "vault_database_secret_backend_role" "status" {
  backend     = local.db_backend
  name        = "vctl-status"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT ON servers TO \"{{name}}\"; GRANT SELECT,INSERT,UPDATE ON server_status TO \"{{name}}\";",
  ]
}

# migrator: SET ROLE to the stable owner for schema changes
resource "vault_database_secret_backend_role" "migrator" {
  backend     = local.db_backend
  name        = "vctl-migrator"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT ${var.pg_migration_owner} TO \"{{name}}\";",
  ]
}
