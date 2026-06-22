# vctl-node policy for node-agent status reporting.
# The agent can report runtime status only; it cannot read inventory secrets or
# sign SSH certificates.

path "database/creds/vctl-status" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
