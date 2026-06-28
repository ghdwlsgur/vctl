# External identity groups are the server-enforced authorization boundary.
# PostgreSQL command grants remain useful as a narrower client-side control, but
# they cannot grant capabilities that the token does not already have here.

# Admins: inventory writes + CA + RBAC management.
resource "vault_identity_group" "vctl_admins" {
  count    = var.enable_oidc ? 1 : 0
  name     = "vctl-admins"
  type     = "external"
  policies = ["vctl-admin", "vctl-ssh", "vctl-auditor"]
  metadata = {
    purpose = "vctl administrators: manage inventory/CA and the app-layer RBAC"
  }
}


resource "vault_identity_group" "vctl_ssh_users" {
  count    = var.enable_oidc ? 1 : 0
  name     = "vctl-ssh-users"
  type     = "external"
  policies = ["vctl-ssh"]
  metadata = {
    purpose = "users allowed to request vctl SSH certificates"
  }
}

resource "vault_identity_group_alias" "vctl_ssh_users" {
  count          = var.enable_oidc ? 1 : 0
  name           = var.oidc_ssh_group
  mount_accessor = vault_jwt_auth_backend.oidc[0].accessor
  canonical_id   = vault_identity_group.vctl_ssh_users[0].id
}

resource "vault_identity_group" "vctl_auditors" {
  count    = var.enable_oidc ? 1 : 0
  name     = "vctl-auditors"
  type     = "external"
  policies = ["vctl-auditor"]
  metadata = {
    purpose = "users allowed to read SSH and kernel audit data"
  }
}

resource "vault_identity_group_alias" "vctl_auditors" {
  count          = var.enable_oidc ? 1 : 0
  name           = var.oidc_auditor_group
  mount_accessor = vault_jwt_auth_backend.oidc[0].accessor
  canonical_id   = vault_identity_group.vctl_auditors[0].id
}

resource "vault_identity_group_alias" "vctl_admins" {
  count          = var.enable_oidc ? 1 : 0
  name           = var.oidc_admin_group # GitLab group name as it appears in groups_direct
  mount_accessor = vault_jwt_auth_backend.oidc[0].accessor
  canonical_id   = vault_identity_group.vctl_admins[0].id
}
