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

# `vctl k8s token` — read-only cluster tokens (vctl v0.8.0).
# Cluster viewing sits with SSH access rather than the login baseline: the
# builtin `view` ClusterRole cannot read Secrets but does read pod logs and
# ConfigMaps. `+` is one mount segment (kubernetes/<cluster>). Every mint is an
# access_log row through vctl-audit-writer above.
path "kubernetes/+/creds/viewer" {
  capabilities = ["update"]
}
