# Server-enforced SSH authorization. Attach only through an approved identity
# group; the CLI's PostgreSQL command grants are defense in depth, not the gate.
path "ssh/sign/sre-core" {
  capabilities = ["update"]
}

path "ssh/config/ca" {
  capabilities = ["read"]
}

# Best-effort client access records use a write-only database role.
path "database/creds/vctl-audit-writer" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
