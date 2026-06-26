# vctl-admin policy: inventory writes, CA operations, and RBAC management.
# SSH signing is NOT here — it's the separate vctl-ssh policy (admins get ssh via
# the vctl-admins group, see groups.tf). Admin = manage inventory + CA + who can
# do what (the vctl-* policies and their group mappings).

# CA public key read + config management (rotation/set is an admin op).
path "ssh/config/ca" {
  capabilities = ["read", "update"]
}

# Inventory read/write credentials.
path "database/creds/vctl-ro" {
  capabilities = ["read"]
}
path "database/creds/vctl-rw" {
  capabilities = ["read"]
}
path "database/creds/vctl-migrator" {
  capabilities = ["read"]
}

# DB engine root credential rotation.
path "database/rotate-root/vctl-pg" {
  capabilities = ["update"]
}

# --- RBAC management (group-based) -----------------------------------------
# Edit the vctl-* policies and the OIDC group -> policy mappings, so an admin can
# change who is admin / who can ssh. Scoped to vctl-* names to keep the org-wide
# groups/policies (e.g. sre-admin, owned by vault-iac) out of reach.
path "sys/policies/acl" {
  capabilities = ["list"]
}
path "sys/policies/acl/vctl-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# External identity groups (GitLab-group-backed) carrying vctl-* policies.
path "identity/group" {
  capabilities = ["list"]
}
path "identity/group/name" {
  capabilities = ["list"]
}
path "identity/group/name/vctl-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
# id-based read resolves a group's canonical_id when managing its alias.
path "identity/group/id" {
  capabilities = ["list"]
}
path "identity/group/id/*" {
  capabilities = ["read"]
}

# Group aliases bind a GitLab group name to an identity group.
path "identity/group-alias" {
  capabilities = ["create", "update", "list"]
}
path "identity/group-alias/id/*" {
  capabilities = ["read", "update", "delete"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
