# AppRoles for non-interactive auto-auth. Periodic service tokens; secret_ids are
# minted per host/workstation at use (boot-time injection), never stored here.
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
}

# vctl-collector: host audit daemons → vctl-rw.
resource "vault_approle_auth_backend_role" "collector" {
  backend            = vault_auth_backend.approle.path
  role_name          = "vctl-collector"
  token_policies     = ["vctl-collector"]
  token_ttl          = 3600
  token_max_ttl      = 0
  token_period       = 86400
  token_type         = "service"
  secret_id_ttl      = 2592000
  secret_id_num_uses = 0
}

# vctl-host: full host stack (collector + watch-sessions + node-agent) → vctl-rw + vctl-status.
resource "vault_approle_auth_backend_role" "host" {
  backend            = vault_auth_backend.approle.path
  role_name          = "vctl-host"
  token_policies     = ["vctl-host"]
  token_ttl          = 3600
  token_max_ttl      = 0
  token_period       = 86400
  token_type         = "service"
  secret_id_ttl      = 2592000
  secret_id_num_uses = 0
}

# vctl-node: node-agent only (status reporting) → vctl-status. Least privilege
# for hosts that run the node-agent without the audit stack (no DB write).
resource "vault_approle_auth_backend_role" "node" {
  backend            = vault_auth_backend.approle.path
  role_name          = "vctl-node"
  token_policies     = ["vctl-node"]
  token_ttl          = 3600
  token_max_ttl      = 0
  token_period       = 86400
  token_type         = "service"
  secret_id_ttl      = 2592000
  secret_id_num_uses = 0
}

# vctl-user: optional workstation auto-auth (shared identity — humans use OIDC).
resource "vault_approle_auth_backend_role" "user" {
  backend            = vault_auth_backend.approle.path
  role_name          = "vctl-user"
  token_policies     = ["vctl-user"]
  token_ttl          = 3600
  token_max_ttl      = 0
  token_period       = 86400
  token_type         = "service"
  secret_id_ttl      = 0
  secret_id_num_uses = 0
}
