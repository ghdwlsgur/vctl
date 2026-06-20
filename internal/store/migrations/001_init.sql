-- vctl 중앙 인벤토리 스키마 (비밀 0)
CREATE TABLE IF NOT EXISTS servers (
    id             BIGSERIAL PRIMARY KEY,
    hostname       TEXT UNIQUE NOT NULL,
    ip             INET NOT NULL,
    ssh_port       INT  NOT NULL DEFAULT 22,
    ssh_user       TEXT NOT NULL DEFAULT 'ubuntu',
    jump_via       TEXT,                       -- nullable: 점프 호스트 hostname
    dc             TEXT NOT NULL,              -- incheon | seoul-onprem
    ca_role        TEXT NOT NULL DEFAULT 'sre-core',
    ca_key_version INT  NOT NULL DEFAULT 1,    -- 무중단 CA 교체 추적
    ca_applied_at  TIMESTAMPTZ,
    last_seen_up   TIMESTAMPTZ,
    tags           JSONB NOT NULL DEFAULT '{}',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_servers_dc ON servers (dc);

-- CA 버전 상태 (무중단 로테이션: active → retiring → retired)
CREATE TABLE IF NOT EXISTS ca_keys (
    version     INT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at  TIMESTAMPTZ
);

-- 접속 감사 (Vault audit 과 별개의 인벤토리 관점 기록)
CREATE TABLE IF NOT EXISTS access_log (
    id          BIGSERIAL PRIMARY KEY,
    vault_user  TEXT,
    hostname    TEXT,
    cert_serial TEXT,
    signed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    ok          BOOLEAN
);
