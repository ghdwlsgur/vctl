-- Session-stamped kernel audit.
--
-- Ties an SSH cert serial (who, from access_log) to the per-host process/file/
-- network events that the session produced. Two uses at once:
--   1. audit/forensics — "who did what on which host, when"
--   2. dataset — structured record of SRE work per host, for feeding an agent
--      ("how is X typically diagnosed/fixed on this fleet").
--
-- A host-side collector (Tetragon) ships kernel events; a login-time stamper
-- (PAM + sshd ExposeAuthInfo) records the cert serial -> session mapping so
-- events attribute to a human, not just the shared login user.

CREATE TABLE IF NOT EXISTS audit_session (
    id                 BIGSERIAL PRIMARY KEY,
    cert_serial        TEXT NOT NULL,        -- joins access_log.cert_serial (who)
    vault_user         TEXT,                 -- resolved human identity (cert key id)
    hostname           TEXT NOT NULL,        -- target host
    login_user         TEXT,                 -- shared OS user: ubuntu/rocky/root
    source_ip          INET,
    session_leader_pid INT,                  -- sshd session leader pid on the host
    cgroup_id          BIGINT,               -- cgroup scoping the session's processes
    started_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at           TIMESTAMPTZ,
    summary            TEXT,                 -- optional intent/outcome (human or agent)
    UNIQUE (hostname, session_leader_pid, started_at)
);

-- One process/file/network event observed inside a session.
-- session_id is nullable: the collector may land events before the stamper has
-- linked the session, so cert_serial/hostname are denormalized for standalone use.
CREATE TABLE IF NOT EXISTS kernel_event (
    id          BIGSERIAL PRIMARY KEY,
    session_id  BIGINT REFERENCES audit_session(id) ON DELETE SET NULL,
    cert_serial TEXT,
    hostname    TEXT NOT NULL,
    ts          TIMESTAMPTZ NOT NULL,
    kind        TEXT NOT NULL,               -- exec | exit | open | connect
    pid         INT,
    ppid        INT,
    cgroup_id   BIGINT,
    exe         TEXT,                        -- /usr/bin/vi  (binary is a reserved word)
    args        TEXT,                        -- full argv as a single string
    cwd         TEXT,
    uid         INT,
    filename    TEXT,                        -- kind=open
    dest_addr   TEXT,                        -- kind=connect (host:port)
    exit_code   INT                          -- kind=exit
);

-- Backfill (idempotent) for any pre-existing partial schema. MUST precede the
-- indexes that reference these columns — on a pre-existing table CREATE TABLE
-- IF NOT EXISTS is a no-op and would otherwise leave columns missing.
ALTER TABLE audit_session ADD COLUMN IF NOT EXISTS summary TEXT;
ALTER TABLE audit_session ADD COLUMN IF NOT EXISTS cgroup_id BIGINT;
ALTER TABLE kernel_event  ADD COLUMN IF NOT EXISTS cgroup_id BIGINT;
ALTER TABLE kernel_event  ADD COLUMN IF NOT EXISTS cert_serial TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_session_serial       ON audit_session (cert_serial);
CREATE INDEX IF NOT EXISTS idx_audit_session_host_started ON audit_session (hostname, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_kernel_event_session       ON kernel_event (session_id, ts);
CREATE INDEX IF NOT EXISTS idx_kernel_event_host_ts       ON kernel_event (hostname, ts DESC);
CREATE INDEX IF NOT EXISTS idx_kernel_event_serial        ON kernel_event (cert_serial);
