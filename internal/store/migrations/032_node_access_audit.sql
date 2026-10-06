-- Append-only lifecycle records for typed node-agent operations. Request data
-- and output are deliberately excluded; this is attribution, not a transcript.
CREATE TABLE IF NOT EXISTS node_access_audit (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    request_id  TEXT NOT NULL,
    phase       TEXT NOT NULL CHECK (phase IN ('started', 'finished')),
    operator    TEXT NOT NULL,
    hostname    TEXT NOT NULL REFERENCES servers(hostname),
    operation   TEXT NOT NULL,
    started_at  TIMESTAMPTZ NOT NULL,
    ended_at    TIMESTAMPTZ,
    outcome     TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (request_id, phase)
);

CREATE INDEX IF NOT EXISTS idx_node_access_audit_host_time
    ON node_access_audit (hostname, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_node_access_audit_operator_time
    ON node_access_audit (operator, recorded_at DESC);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_node_access_audit') THEN
        GRANT INSERT ON node_access_audit TO vctl_node_access_audit;
        GRANT USAGE, SELECT ON SEQUENCE node_access_audit_id_seq TO vctl_node_access_audit;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_audit_ro') THEN
        GRANT SELECT ON node_access_audit TO vctl_audit_ro;
    END IF;
END $$;
