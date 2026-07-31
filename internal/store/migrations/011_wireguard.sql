-- WireGuard topology and runtime state, collected by `vctl wg sync`.
--
-- Each gateway is read over SSH with `wg show all dump` + `ip addr`, then
-- upserted here.
--
-- No secrets are stored. Interface private keys and peer preshared keys are
-- dropped during parsing and never reach this schema; only public keys are
-- persisted, and a public key is a peer identifier rather than a secret.
--
-- wg_interfaces  : static configuration of each host's WG interfaces
-- wg_peers       : peers per interface (pubkey, endpoint, allowed-ips) — the
--                  edges of the topology
-- wg_peer_status : latest runtime sample per peer (handshake, rx/tx), for
--                  monitoring

CREATE TABLE IF NOT EXISTS wg_interfaces (
    host        TEXT NOT NULL,          -- servers.hostname of the gateway that was polled
    iface       TEXT NOT NULL,          -- wg0, wg1, wg-seoul ...
    listen_port INT,
    public_key  TEXT NOT NULL,
    fwmark      BIGINT,
    address     INET[] NOT NULL DEFAULT '{}',  -- interface addresses, from `ip addr`
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, iface)
);
CREATE INDEX IF NOT EXISTS idx_wg_interfaces_pubkey ON wg_interfaces (public_key);

CREATE TABLE IF NOT EXISTS wg_peers (
    host                 TEXT NOT NULL,     -- gateway this peer is configured on
    iface                TEXT NOT NULL,     -- which interface the peer belongs to
    peer_pubkey          TEXT NOT NULL,     -- peer public key (the identifier)
    endpoint             TEXT,              -- host:port (may be dynamic)
    allowed_ips          TEXT[] NOT NULL DEFAULT '{}',
    persistent_keepalive INT,
    label                TEXT,              -- human-assigned identity, filled in at view time
    collected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, iface, peer_pubkey)
);
CREATE INDEX IF NOT EXISTS idx_wg_peers_pubkey ON wg_peers (peer_pubkey);

CREATE TABLE IF NOT EXISTS wg_peer_status (
    host             TEXT NOT NULL,
    iface            TEXT NOT NULL,
    peer_pubkey      TEXT NOT NULL,
    latest_handshake TIMESTAMPTZ,           -- NULL = no handshake has ever completed
    rx_bytes         BIGINT NOT NULL DEFAULT 0,
    tx_bytes         BIGINT NOT NULL DEFAULT 0,
    sampled_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host, iface, peer_pubkey)
);
CREATE INDEX IF NOT EXISTS idx_wg_peer_status_handshake ON wg_peer_status (latest_handshake DESC);
