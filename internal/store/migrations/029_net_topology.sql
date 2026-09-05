-- Declared network topology: the underlay and the patterns laid over it.
--
-- WireGuard collection knows only what `wg show` says — interfaces, peers,
-- AllowedIPs, handshakes. That is the overlay's runtime, and nothing in it says
-- which physical host a VM runs on, which farm that host belongs to, which
-- network an address lives in, or which edge device and public uplink a tunnel
-- actually transits. Those facts lived in a document, and the dashboard's
-- layout encoded the one pattern (hub-and-spoke) they happened to form.
--
-- These two tables make the underlay and the access patterns first-class data,
-- so the topology renders from rows rather than from code. Two tables, not one
-- per kind: the point is that a new farm, edge or tunnel pattern is an INSERT,
-- not a migration. Kind-specific detail goes in `attrs` (JSONB).
--
-- Networks are keyed by identity, not CIDR. One farm here carries three
-- distinct networks that all use 10.20.0.0/24; a CIDR key would merge them and
-- hide exactly the ambiguity that matters. The id is `net/<farm>/<name>`.
--
-- Paths and failure domains are deliberately NOT stored. They are derived by
-- walking relations, so they cannot drift from the facts they describe.
-- Collection never writes these tables.
CREATE TABLE IF NOT EXISTS net_entities (
    id          TEXT PRIMARY KEY,               -- <kind>/<name>; networks: net/<farm>/<name>
    kind        TEXT NOT NULL
                CHECK (kind IN ('site','farm','physical-host','vm','network','tunnel','edge','egress')),
    label       TEXT NOT NULL DEFAULT '',
    site        TEXT NOT NULL DEFAULT '',        -- denormalised site for grouping; empty = unknown
    attrs       JSONB NOT NULL DEFAULT '{}',     -- kind-specific: network.cidr, egress.public_ip, tunnel.host/iface ...
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_net_entities_kind ON net_entities (kind);
CREATE INDEX IF NOT EXISTS idx_net_entities_site ON net_entities (site) WHERE site <> '';

-- A relation is a typed, directed edge between two declared entities.
--   placed-on    vm            -> physical-host      (runtime placement; may move)
--   member-of    host|farm     -> farm|site          (static membership)
--   attached-to  tunnel|vm     -> network            (which fabric an interface sits on)
--   transits     tunnel        -> edge|egress        (ordered by attrs.order)
--   carries      tunnel        -> network            (attrs.method: direct|proxy|dnat, plus method detail)
-- "If dst dies, src dies" holds for placed-on, member-of and transits; that is
-- what the failure-domain derivation walks.
CREATE TABLE IF NOT EXISTS net_relations (
    src_id      TEXT NOT NULL REFERENCES net_entities(id) ON DELETE CASCADE,
    dst_id      TEXT NOT NULL REFERENCES net_entities(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL
                CHECK (kind IN ('placed-on','member-of','attached-to','transits','carries')),
    attrs       JSONB NOT NULL DEFAULT '{}',
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (src_id, dst_id, kind)
);
CREATE INDEX IF NOT EXISTS idx_net_relations_dst  ON net_relations (dst_id);
CREATE INDEX IF NOT EXISTS idx_net_relations_kind ON net_relations (kind);

-- Production migration runs after group-role bootstrap, but local/test
-- databases may not have those roles.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_ro') THEN
        GRANT SELECT ON net_entities, net_relations TO vctl_ro;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON net_entities, net_relations TO vctl_rw;
    END IF;
END $$;
