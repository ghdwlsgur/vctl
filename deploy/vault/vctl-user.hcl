# vctl-user — baseline for every authenticated user (OIDC login + workstation
# AppRole). Vault grants the coarse capability set: SSH cert signing + inventory
# reads. The fine-grained "who may run which command" (including ssh) is enforced
# by the app-layer RBAC (`vctl rbac`), NOT here. vctl-admin adds RBAC management.

# SSH certificate signing — the capability. The `vctl ssh` command itself is
# gated by the app-layer RBAC, which can allow/deny it per user/group.
path "ssh/sign/sre-core" {
  capabilities = ["update"]
}
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
