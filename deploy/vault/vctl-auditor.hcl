# Read-only access to access/session/kernel audit data.
path "database/creds/vctl-audit-ro" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
