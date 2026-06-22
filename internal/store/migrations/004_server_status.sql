-- Runtime host status reported by vctl node-agent.
--
-- `servers` remains the operator-managed source of truth. The agent only
-- updates status for an already registered hostname; it never creates inventory.

CREATE TABLE IF NOT EXISTS server_status (
    hostname           TEXT PRIMARY KEY,
    last_seen_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    agent_version      TEXT,
    os                 TEXT,
    kernel             TEXT,
    uptime_seconds     BIGINT,
    load1              DOUBLE PRECISION,
    memory_used_pct    DOUBLE PRECISION,
    disk_root_used_pct DOUBLE PRECISION,
    sshd_ok            BOOLEAN,
    kubelet_ok         BOOLEAN,
    crio_ok            BOOLEAN,
    docker_ok          BOOLEAN,
    audit_collector_ok BOOLEAN,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_server_status_last_seen ON server_status (last_seen_at DESC);
