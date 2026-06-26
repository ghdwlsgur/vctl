# vctl-ssh policy: the SSH capability, split out from vctl-user so `vctl ssh` is
# gated by group membership. Only identities mapped to this policy (e.g. the
# vctl-admins group, see groups.tf) can sign a cert and connect. Removing this
# from a group instantly revokes ssh without touching inventory access.

# SSH certificate signing — the actual gate for `vctl ssh`.
path "ssh/sign/sre-core" {
  capabilities = ["update"]
}

# Read the CA public key (host trust / status checks).
path "ssh/config/ca" {
  capabilities = ["read"]
}

# Token self lookup / renewal.
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
