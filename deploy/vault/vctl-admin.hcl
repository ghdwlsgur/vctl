# vctl-admin policy for inventory sync, writes, and CA operations.
# Includes vctl-user permissions plus write credentials and CA rotation access.

path "ssh/sign/sre-core" {
  capabilities = ["update"]
}

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

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
