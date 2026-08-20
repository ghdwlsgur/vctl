-- Online DBA indexes for an already-populated vctl database.
--
-- Run with psql in autocommit mode; never wrap this file in BEGIN/COMMIT because
-- PostgreSQL forbids CREATE/DROP INDEX CONCURRENTLY inside a transaction block.

-- A failed concurrent build leaves an index relation behind with
-- indisvalid=false. IF NOT EXISTS alone would skip that broken relation forever,
-- so remove only our invalid targets first and let the statements below rebuild
-- them. \gexec runs each generated DROP as its own autocommit statement.
SELECT format('DROP INDEX CONCURRENTLY IF EXISTS %I.%I;', n.nspname, c.relname)
FROM pg_index i
JOIN pg_class c ON c.oid=i.indexrelid
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public'
  AND (NOT i.indisvalid OR NOT i.indisready)
  AND c.relname IN (
    'idx_servers_ip',
    'idx_servers_extra_ips_gin',
    'idx_server_status_observed_ips_gin',
    'idx_audit_session_serial_started',
    'idx_audit_session_host_cgroup_started',
    'idx_audit_session_unended',
    'idx_audit_session_started',
    'idx_access_log_cert_signed',
    'idx_openstack_instances_active_listing',
    'idx_openstack_instances_active_observed',
    'idx_openstack_instances_missing'
  )
\gexec

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_servers_ip ON servers (ip);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_servers_extra_ips_gin ON servers USING gin (extra_ips);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_server_status_observed_ips_gin
    ON server_status USING gin (observed_ips);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_session_serial_started
    ON audit_session (cert_serial, started_at DESC)
    WHERE cert_serial IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_session_host_cgroup_started
    ON audit_session (hostname, cgroup_id, started_at DESC)
    WHERE cgroup_id IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_session_unended
    ON audit_session (hostname, started_at DESC)
    WHERE ended_at IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_session_started
    ON audit_session (started_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_log_cert_signed
    ON access_log (cert_serial, signed_at DESC)
    WHERE cert_serial IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_openstack_instances_active_listing
    ON openstack_instances (deployment_id, name, instance_id)
    WHERE missing_since IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_openstack_instances_active_observed
    ON openstack_instances (deployment_id, observed_at)
    WHERE missing_since IS NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_openstack_instances_missing
    ON openstack_instances (missing_since)
    WHERE missing_since IS NOT NULL;

-- The composite index above covers equality on cert_serial as well as the old
-- single-column index. Drop the old one only after PostgreSQL says its replacement
-- is valid; this keeps a failed/resumed build from removing the last good path.
SELECT 'DROP INDEX CONCURRENTLY IF EXISTS public.idx_audit_session_serial;'
WHERE EXISTS (
  SELECT 1 FROM pg_index i
  JOIN pg_class c ON c.oid=i.indexrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public'
    AND c.relname='idx_audit_session_serial_started'
    AND i.indisvalid AND i.indisready
)
\gexec
