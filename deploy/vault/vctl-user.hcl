# vctl-user policy for regular team members.
# Inventory reads only. SSH cert signing is NOT here — it lives in the separate
# vctl-ssh policy, granted by group (see groups.tf). So a plain OIDC login can
# list inventory but cannot `vctl ssh` unless mapped to vctl-ssh.

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
