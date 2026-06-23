-- node-agent now reports a liveness heartbeat only (load/memory/disk); the
-- per-service health probes were removed. Drop the now-unused columns.
-- IF EXISTS keeps this idempotent (the runner re-applies all migrations).
ALTER TABLE server_status
    DROP COLUMN IF EXISTS sshd_ok,
    DROP COLUMN IF EXISTS kubelet_ok,
    DROP COLUMN IF EXISTS crio_ok,
    DROP COLUMN IF EXISTS docker_ok,
    DROP COLUMN IF EXISTS audit_collector_ok;
