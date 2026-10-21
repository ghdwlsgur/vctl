-- Hardware specs and asset notes for bare-metal hosts.
--
-- The SRE asset sheet mixed two kinds of fact in one row, and they belong to
-- different writers:
--
--   server_specs   what the machine says about itself: vendor, model, serial,
--                  CPUs, DIMMs, disks, NIC ports. Written by collectors (the
--                  node-agent from SMBIOS/sysfs, the vSphere poller for ESXi),
--                  replaced whole on every collection.
--   server_assets  what only people know: IDC, rack, labels, rack units, usage,
--                  purpose, solution, owning department, RAID layout. Written
--                  by operators; no collector role can touch it.
--
-- Keeping them apart is what lets a collector overwrite its row without ever
-- losing an operator's note, and lets the view flag a sheet that disagrees
-- with the machine (a serial typed by hand against the one SMBIOS reports).

CREATE TABLE IF NOT EXISTS server_specs (
    hostname     TEXT PRIMARY KEY REFERENCES servers(hostname) ON DELETE CASCADE ON UPDATE CASCADE,
    source       TEXT NOT NULL,             -- agent | vsphere
    spec         JSONB NOT NULL,            -- hwspec.Spec
    collector    TEXT,                      -- version of whatever wrote it
    observed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT server_specs_source_check CHECK (source IN ('agent','vsphere'))
);

CREATE TABLE IF NOT EXISTS server_assets (
    hostname      TEXT PRIMARY KEY REFERENCES servers(hostname) ON DELETE CASCADE ON UPDATE CASCADE,
    idc           TEXT,
    rack          TEXT,
    label         TEXT,   -- 신규 라벨
    legacy_label  TEXT,   -- 기존 Label
    rack_units    TEXT,   -- Unit, e.g. 2U
    usage         TEXT,   -- 사용여부: 사용중, 미사용, ...
    purpose       TEXT,   -- 용도
    solution      TEXT,   -- 솔루션
    department    TEXT,   -- 사용부서
    raid          TEXT,   -- RAID 구성; the OS sees the logical volume, not the layout
    note          TEXT,
    updated_by    TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_ro') THEN
        GRANT SELECT ON server_specs, server_assets TO vctl_ro;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_status') THEN
        -- The collectors write specs through the heartbeat role. Assets are
        -- deliberately absent: a host must not be able to rewrite its own rack
        -- or owner.
        GRANT SELECT, INSERT, UPDATE ON server_specs TO vctl_status;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON server_specs, server_assets TO vctl_rw;
    END IF;
END $$;
