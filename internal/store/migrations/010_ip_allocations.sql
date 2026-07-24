-- 192.168.201.0/24 IP 대장 (IPAM).
--
-- `servers` 는 vctl sync 가 자동 관리하는 SSH 대상 인벤토리라, 개인 단말·오픈스택 VM·
-- Floating IP·DNAT VIP 처럼 SSH 대상이 아닌 주소까지 담을 수 없다. 이 테이블은 운영자가
-- 손으로 관리하는 대역 대장으로, sync/Upsert 가 절대 건드리지 않는다. 물리 서버 행은
-- hostname 으로 servers 와 느슨히 연계(join)할 수 있으나 FK 제약은 걸지 않는다 —
-- servers 에 아직 없거나 이미 삭제된 호스트도 대장에는 남을 수 있어야 하기 때문이다.
CREATE TABLE IF NOT EXISTS ip_allocations (
    ip         INET PRIMARY KEY,
    owner      TEXT NOT NULL DEFAULT '',        -- 사람 이름 또는 팀 (홍진혁 / SRE / AI플랫폼팀 ...)
    kind       TEXT NOT NULL,                   -- personal | server | vm | floating-ip | dnat-vip
    label      TEXT NOT NULL DEFAULT '',        -- 대상명: hostname / VM명 / port명 / "개인 노트북"
    hostname   TEXT,                            -- kind=server 일 때 servers.hostname 연계(nullable)
    os         TEXT,                            -- 개인 단말 OS (Mac/Windows)
    project    TEXT,                            -- 오픈스택 프로젝트 또는 용도 (admin / ai-platform / NAT 시연 ...)
    farm       TEXT,                            -- OpenStack 팜 라벨 A/B/C/D
    farm_vip   INET,                            -- 팜 external VIP (.150/.245/.130/.90)
    rack       TEXT,                            -- 랙 위치 R1/37U-38U 등
    location   TEXT,                            -- 을지로 10F 서버실 ...
    wg_tunnel  TEXT,                            -- wg0/wg1/wg2/wg3 (해당 시)
    status     TEXT NOT NULL DEFAULT 'active',  -- active | broken | reserved
    note       TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ip_alloc_owner ON ip_allocations (owner);
CREATE INDEX IF NOT EXISTS idx_ip_alloc_kind  ON ip_allocations (kind);
CREATE INDEX IF NOT EXISTS idx_ip_alloc_farm  ON ip_allocations (farm);
