-- vctl central inventory schema. No secrets are stored here.
CREATE TABLE IF NOT EXISTS servers (
    id             BIGSERIAL PRIMARY KEY,
    hostname       TEXT UNIQUE NOT NULL,
    ip             INET NOT NULL,
    ssh_port       INT  NOT NULL DEFAULT 22,
    ssh_user       TEXT NOT NULL DEFAULT 'ubuntu',
    jump_via       TEXT,                       -- nullable jump host hostname
    dc             TEXT NOT NULL,              -- incheon | seoul-onprem
    ca_role        TEXT NOT NULL DEFAULT 'sre-core',
    ca_key_version INT  NOT NULL DEFAULT 1,    -- tracks zero-downtime CA rotation
    ca_applied_at  TIMESTAMPTZ,
    last_seen_up   TIMESTAMPTZ,
    tags           JSONB NOT NULL DEFAULT '{}',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_servers_dc ON servers (dc);

-- CA version state for zero-downtime rotation.
CREATE TABLE IF NOT EXISTS ca_keys (
    version     INT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ
);

-- Inventory-level access audit, separate from Vault audit logs.
CREATE TABLE IF NOT EXISTS access_log (
    id          BIGSERIAL PRIMARY KEY,
    vault_user  TEXT,
    hostname    TEXT,
    cert_serial TEXT,
    signed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ok          BOOLEAN,
    source_ip   INET,
    source_addr TEXT,
    client_host TEXT,
    client_user TEXT,
    target_addr TEXT,
    jump_via    TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_log_signed_at ON access_log (signed_at DESC);
CREATE INDEX IF NOT EXISTS idx_access_log_source_ip ON access_log (source_ip);

ALTER TABLE access_log ADD COLUMN IF NOT EXISTS source_ip INET;
ALTER TABLE access_log ADD COLUMN IF NOT EXISTS source_addr TEXT;
ALTER TABLE access_log ADD COLUMN IF NOT EXISTS client_host TEXT;
ALTER TABLE access_log ADD COLUMN IF NOT EXISTS client_user TEXT;
ALTER TABLE access_log ADD COLUMN IF NOT EXISTS target_addr TEXT;
ALTER TABLE access_log ADD COLUMN IF NOT EXISTS jump_via TEXT;
ALTER TABLE access_log ADD COLUMN IF NOT EXISTS error TEXT;
