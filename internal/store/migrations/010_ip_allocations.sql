-- Operator-maintained IP ledger (IPAM).
--
-- `servers` is the SSH target inventory that `vctl sync` manages automatically,
-- so it cannot hold addresses that are not SSH targets: personal devices,
-- OpenStack VMs, floating IPs, DNAT VIPs. This table is the hand-maintained
-- ledger for those, and sync/Upsert never touch it. Rows of kind=server can be
-- joined loosely to `servers` on hostname, but no FK constraint is declared —
-- the ledger must be able to hold a host that is not in `servers` yet, or one
-- that has already been removed from it.
CREATE TABLE IF NOT EXISTS ip_allocations (
    ip         INET PRIMARY KEY,
    owner      TEXT NOT NULL DEFAULT '',        -- person or team (e.g. sre, platform)
    kind       TEXT NOT NULL,                   -- personal | server | vm | floating-ip | dnat-vip
    label      TEXT NOT NULL DEFAULT '',        -- what it is: hostname / VM name / port name / "laptop"
    hostname   TEXT,                            -- links to servers.hostname when kind=server (nullable)
    os         TEXT,                            -- personal device OS (Mac/Windows)
    project    TEXT,                            -- OpenStack project or purpose (e.g. admin, platform)
    farm       TEXT,                            -- OpenStack farm label
    farm_vip   INET,                            -- the farm's external VIP
    rack       TEXT,                            -- rack position (e.g. R1/37U-38U)
    location   TEXT,                            -- site or room
    wg_tunnel  TEXT,                            -- wg0/wg1/wg2/... where applicable
    status     TEXT NOT NULL DEFAULT 'active',  -- active | broken | reserved
    note       TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ip_alloc_owner ON ip_allocations (owner);
CREATE INDEX IF NOT EXISTS idx_ip_alloc_kind  ON ip_allocations (kind);
CREATE INDEX IF NOT EXISTS idx_ip_alloc_farm  ON ip_allocations (farm);
