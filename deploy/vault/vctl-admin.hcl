# vctl-scoped admin: inventory writes, migrations, and vctl's own RBAC.
#
# SSH signing is deliberately NOT here — it lives in vctl-ssh and is granted to
# the same admin group separately, so "can administer vctl" and "can reach every
# host" stay two decisions.
#
# What makes this an admin rather than a writer is the second half: it can edit
# the vctl-* policies and the identity groups that carry them, i.e. it can change
# who is an admin. That power is scoped by name (vctl-*) so it cannot reach the
# org-wide objects owned by the platform root configuration.
#
# NOTE: this file is a reference copy. The applied source of truth is the
# Terraform module that manages Vault configuration; see the repository README.

# --- inventory dynamic credentials (read / write / schema) -------------------
path "database/creds/vctl-ro" {
  capabilities = ["read"]
}
# Reconcile run from a workstation uses the same dedicated role the farm
# controllers hold — vctl-rw is not what that command needs.
path "database/creds/vctl-reconcile" {
  capabilities = ["read"]
}
path "database/creds/vctl-rw" {
  capabilities = ["read"]
}
path "database/creds/vctl-migrator" {
  capabilities = ["read"]
}

# --- RBAC administration (group-based) ---------------------------------------
# Edit the vctl-* policies and the OIDC group -> policy mapping. Scoped to the
# vctl-* namespace so org objects stay out of reach.
path "sys/policies/acl" {
  capabilities = ["list"]
}
path "sys/policies/acl/vctl-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# External identity groups carry the vctl-* policies to their members.
path "identity/group" {
  capabilities = ["list"]
}
path "identity/group/name" {
  capabilities = ["list"]
}
path "identity/group/name/vctl-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
# Reading group ids is needed to resolve canonical_id when managing aliases.
path "identity/group/id" {
  capabilities = ["list"]
}
path "identity/group/id/*" {
  capabilities = ["read"]
}

# Group alias: bind an external group name to an identity group.
path "identity/group-alias" {
  capabilities = ["create", "update", "list"]
}
path "identity/group-alias/id/*" {
  capabilities = ["read", "update", "delete"]
}
