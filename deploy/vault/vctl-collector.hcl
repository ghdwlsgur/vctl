# vctl kernel-audit collector — least privilege.
# The host collector (Tetragon -> kernel_event) and watch-sessions
# (audit_session) append and update lifecycle data. Pruning has its own policy.
# This policy allows only append/session-lifecycle audit ingestion.
path "database/creds/vctl-audit-ingest" {
  capabilities = ["read"]
}
