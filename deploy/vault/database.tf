# Postgres dynamic credentials. The stable owner role (var.pg_migration_owner)
# is a Postgres-side object Terraform can't create cleanly — run postgres-owner.sh
# first. Rotate the root credential after apply: vault write -f database/rotate-root/vctl-pg
resource "vault_mount" "database" {
  path = "database"
  type = "database"
}

resource "vault_database_secret_backend_connection" "vctl_pg" {
  backend       = vault_mount.database.path
  name          = "vctl-pg"
  allowed_roles = ["vctl-ro", "vctl-rw", "vctl-status", "vctl-migrator"]

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

# ro: inventory reads
resource "vault_database_secret_backend_role" "ro" {
  backend     = local.db_backend
  name        = "vctl-ro"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO \"{{name}}\";",
  ]
}

# rw: audit writes / sync
resource "vault_database_secret_backend_role" "rw" {
  backend     = local.db_backend
  name        = "vctl-rw"
  db_name     = local.db_name
  default_ttl = 3600
  max_ttl     = 14400
  creation_statements = [
    "${local.create_login} GRANT USAGE,CREATE ON SCHEMA public TO \"{{name}}\"; GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\"; GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\"; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO \"{{name}}\";",
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
