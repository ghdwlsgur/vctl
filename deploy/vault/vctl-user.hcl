# vctl-user policy for regular team members.
# Minimum permissions for SSH certificate signing and inventory reads.

# SSH certificate signing.
path "ssh/sign/sre-core" {
  capabilities = ["update"]
}

# Read the CA public key for status checks.
path "ssh/config/ca" {
  capabilities = ["read"]
}

# Short-lived read-only DB credentials for inventory reads.
path "database/creds/vctl-ro" {
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
