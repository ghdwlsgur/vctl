# Baseline for every authenticated user. SSH signing and audit reads are separate
# policies so bypassing the CLI cannot bypass authorization.

# Short-lived read-only DB credentials for inventory reads.
path "database/creds/vctl-ro" {
  capabilities = ["read"]
}

path "database/creds/vctl-identity" {
  capabilities = ["read"]
}

# Token self lookup.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Token self renewal for vctl agent, exec, and token.
path "auth/token/renew-self" {
  capabilities = ["update"]
}
