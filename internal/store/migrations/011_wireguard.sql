-- WireGuard 토폴로지/상태 저장 (vctl wg sync 로 수집).
--
-- 각 게이트웨이에서 `wg show all dump` + `ip addr` 를 SSH 로 읽어 upsert 한다.
-- 비밀은 저장하지 않는다: 인터페이스 개인키·peer preshared-key 는 파싱 단계에서
-- 버리고 공개키만 싣는다(공개키는 peer 식별자이지 비밀이 아니다).
--
-- wg_interfaces  : 호스트별 WG 인터페이스(wg0/wg1/...)의 정적 구성
-- wg_peers       : 인터페이스별 peer(공개키·endpoint·allowed-ips) — 토폴로지 엣지
-- wg_peer_status : peer 별 최신 런타임 스냅샷(handshake·rx/tx) — monitoring 용

CREATE TABLE IF NOT EXISTS wg_interfaces (
    host        TEXT NOT NULL,          -- servers.hostname (수집 대상 게이트웨이)
    iface       TEXT NOT NULL,          -- wg0, wg1, wg-seoul ...
    listen_port INT,
    public_key  TEXT NOT NULL,
    fwmark      BIGINT,
    address     INET[] NOT NULL DEFAULT '{}',  -- ip addr 로 채운 인터페이스 주소
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, iface)
);
CREATE INDEX IF NOT EXISTS idx_wg_interfaces_pubkey ON wg_interfaces (public_key);

CREATE TABLE IF NOT EXISTS wg_peers (
    host                 TEXT NOT NULL,     -- 이 peer 가 설정된 게이트웨이
    iface                TEXT NOT NULL,     -- 어느 인터페이스의 peer 인지
    peer_pubkey          TEXT NOT NULL,     -- peer 공개키(식별자)
    endpoint             TEXT,              -- host:port (동적일 수 있음)
    allowed_ips          TEXT[] NOT NULL DEFAULT '{}',
    persistent_keepalive INT,
    label                TEXT,              -- 사람이 붙인 정체(뷰 단계에서 보강)
    collected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, iface, peer_pubkey)
);
CREATE INDEX IF NOT EXISTS idx_wg_peers_pubkey ON wg_peers (peer_pubkey);

CREATE TABLE IF NOT EXISTS wg_peer_status (
    host             TEXT NOT NULL,
    iface            TEXT NOT NULL,
    peer_pubkey      TEXT NOT NULL,
    latest_handshake TIMESTAMPTZ,           -- NULL = 핸드셰이크 이력 없음
    rx_bytes         BIGINT NOT NULL DEFAULT 0,
    tx_bytes         BIGINT NOT NULL DEFAULT 0,
    sampled_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, iface, peer_pubkey)
);
CREATE INDEX IF NOT EXISTS idx_wg_peer_status_handshake ON wg_peer_status (latest_handshake DESC);
