-- Operator-owned identities and physical placements for WireGuard endpoints.
--
-- `wg show` can identify a peer only by public key and its current endpoint.
-- The endpoint may sit behind NAT and may itself be a VM, so neither value is a
-- stable human/physical identity. This table maps the public key to that
-- identity and, for VMs, to the physical inventory host that currently runs it.
-- Collection never writes this table.
CREATE TABLE IF NOT EXISTS wg_endpoint_annotations (
    public_key       TEXT PRIMARY KEY,
    label            TEXT NOT NULL DEFAULT '',
    kind             TEXT NOT NULL DEFAULT 'device', -- vm | physical-host | device | gateway
    underlay_ip      INET,
    tunnel_ip        INET,
    site             TEXT NOT NULL DEFAULT '',
    inventory_host   TEXT NOT NULL DEFAULT '',
    parent_hostname  TEXT NOT NULL DEFAULT '',
    note             TEXT NOT NULL DEFAULT '',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_wg_endpoint_parent
    ON wg_endpoint_annotations (parent_hostname)
    WHERE parent_hostname <> '';

-- Production migration runs after group-role bootstrap, but local/test
-- databases may not have those roles.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_ro') THEN
        GRANT SELECT ON wg_endpoint_annotations TO vctl_ro;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON wg_endpoint_annotations TO vctl_rw;
    END IF;
END $$;
