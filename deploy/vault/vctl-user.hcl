# Baseline for every authenticated user (workstation / OIDC).
#
# SSH signing is a separate policy (vctl-ssh) granted only to approved identity
# groups, so bypassing the CLI cannot bypass authorization: the app-layer RBAC in
# internal/authz is a second gate on top, never the only one.
#
# NOTE: this file is a reference copy. The applied source of truth is the
# Terraform module that manages Vault configuration; see the repository README.

# --- self-registration --------------------------------------------------------
# `vctl login --register` reads its own role_id and issues itself a secret_id, so
# later runs re-authenticate without a prompt. Scoped to this one role.
path "auth/approle/role/vctl-user/role-id" {
  capabilities = ["read"]
}
path "auth/approle/role/vctl-user/secret-id" {
  capabilities = ["create", "update"]
}

# --- inventory dynamic credentials --------------------------------------------
path "database/creds/vctl-ro" {
  capabilities = ["read"]
}
# vctl-identity backs the seen_users upsert on login (user auto-registration and
# client version tracking) and nothing else.
path "database/creds/vctl-identity" {
  capabilities = ["read"]
}
path "database/creds/vctl-rw" {
  capabilities = ["read"]
}
path "database/creds/vctl-migrator" {
  capabilities = ["read"]
}
