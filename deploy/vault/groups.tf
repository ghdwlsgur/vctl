# RBAC is group-based: external identity groups are backed by GitLab groups (the
# groups_direct claim on the OIDC token). Membership grants the attached vctl-*
# policies at login — on top of the role's base vctl-user. So a plain login =
# vctl-user (ssh capability + inventory reads); a vctl-admins member also gets
# vctl-admin (RBAC management). Count-gated on enable_oidc since the alias binds
# to the OIDC mount accessor.
#
# ssh is NOT gated here — vctl-user already carries the ssh-sign capability for
# everyone, and the app-layer RBAC (`vctl rbac`) decides who may actually run it.
# Vault layer-1 only distinguishes admin (vctl-admin) from user (vctl-user).

# Admins: inventory writes + CA + RBAC management.
resource "vault_identity_group" "vctl_admins" {
  count    = var.enable_oidc ? 1 : 0
  name     = "vctl-admins"
  type     = "external"
  policies = ["vctl-admin"]
  metadata = {
    purpose = "vctl administrators: manage inventory/CA and the app-layer RBAC"
  }
}

resource "vault_identity_group_alias" "vctl_admins" {
  count          = var.enable_oidc ? 1 : 0
  name           = var.oidc_admin_group # GitLab group name as it appears in groups_direct
  mount_accessor = vault_jwt_auth_backend.oidc[0].accessor
  canonical_id   = vault_identity_group.vctl_admins[0].id
}
