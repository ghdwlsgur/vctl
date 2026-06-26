# RBAC is group-based: external identity groups are backed by GitLab groups (the
# groups_direct claim on the OIDC token). Membership in the GitLab group grants the
# attached vctl-* policies at login — on top of the role's base vctl-user. So a
# plain login = vctl-user (inventory reads, no ssh); a vctl-admins member also gets
# vctl-admin + vctl-ssh. Count-gated on enable_oidc since the alias binds to the
# OIDC mount accessor.

# Admins: inventory writes + CA + RBAC management (vctl-admin) AND ssh (vctl-ssh).
resource "vault_identity_group" "vctl_admins" {
  count    = var.enable_oidc ? 1 : 0
  name     = "vctl-admins"
  type     = "external"
  policies = ["vctl-admin", "vctl-ssh"]
  metadata = {
    purpose = "vctl administrators: manage inventory/CA/RBAC and use vctl ssh"
  }
}

resource "vault_identity_group_alias" "vctl_admins" {
  count          = var.enable_oidc ? 1 : 0
  name           = var.oidc_admin_group # GitLab group name as it appears in groups_direct
  mount_accessor = vault_jwt_auth_backend.oidc[0].accessor
  canonical_id   = vault_identity_group.vctl_admins[0].id
}

# To grant ssh WITHOUT admin later: add a second external group mapped to
# ["vctl-ssh"] only and point its alias at the relevant GitLab group. vctl-ssh
# being its own policy keeps that a one-resource change.
