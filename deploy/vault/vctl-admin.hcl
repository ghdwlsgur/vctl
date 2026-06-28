# Inventory/RBAC writes, migration, and CA operations. Vault policy and Identity
# administration intentionally stay in Terraform/platform-admin credentials: a
# token able to rewrite its own policy can elevate itself to all of Vault.

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
path "database/creds/vctl-audit-ro" {
  capabilities = ["read"]
}
path "database/creds/vctl-pruner" {
  capabilities = ["read"]
}
path "database/creds/vctl-migrator" {
  capabilities = ["read"]
}

# DB engine root credential rotation.
path "database/rotate-root/vctl-pg" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
