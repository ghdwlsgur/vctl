# NOT APPLIED. Unlike its siblings in this directory, no policy by this name
# exists in Vault (checked 2026-07-29) and the Terraform module that owns the
# applied configuration does not define one.
#
# The vctl-pruner *database role* does exist, so the retention job could in
# principle take a dynamic credential — but nothing can reach it, because no
# policy grants database/creds/vctl-pruner to anyone. The job that actually runs
# does not go through Vault at all: it connects over the pod-local socket as the
# database owner (see deploy/audit/prune-cronjob.yaml).
#
# Keep this file only as the shape a Vault-authenticated pruner would take.
# Before relying on it, add the policy to the Terraform module first — a file
# here changes nothing on its own.
path "database/creds/vctl-pruner" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
