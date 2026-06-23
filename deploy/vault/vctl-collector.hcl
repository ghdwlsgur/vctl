# vctl kernel-audit collector — least privilege.
# The host collector (Tetragon -> kernel_event), watch-sessions (audit_session),
# and the prune CronJob need dynamic RW credentials to write to central Postgres.
# This policy allows ONLY issuing database/creds/vctl-rw — no Vault/SSH/KV access.
path "database/creds/vctl-rw" {
  capabilities = ["read"]
}
