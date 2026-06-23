# vctl on-prem host agents (combined) — least privilege.
# One on-prem host runs the full stack:
#   - collector / watch-sessions -> database/creds/vctl-rw     (audit writes)
#   - node-agent                 -> database/creds/vctl-status  (status reports)
# All three authenticate with the same AppRole under /etc/vctl, so this grants
# both DB roles. Nothing else (no SSH signing, KV, sys). Token self-renew only.
path "database/creds/vctl-rw" {
  capabilities = ["read"]
}

path "database/creds/vctl-status" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
