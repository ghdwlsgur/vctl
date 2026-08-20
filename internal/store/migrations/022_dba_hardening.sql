-- DBA hardening for the access paths that grow with the fleet.
--
-- Constraints are NOT VALID on purpose. They protect every new write without
-- turning a deploy into an outage because one legacy row predates the rule.
-- A DBA can inspect and VALIDATE each constraint after cleaning old rows; that
-- validation is an operational decision, not something application startup
-- should guess at.

-- Indexes for these constraints and access paths live in
-- deploy/vault/postgres-online-indexes.sql. CREATE INDEX CONCURRENTLY cannot run
-- inside the migration runner's transaction; using ordinary CREATE INDEX here
-- would block audit ingestion until every pending migration committed.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'servers_ssh_port_check') THEN
        ALTER TABLE servers ADD CONSTRAINT servers_ssh_port_check
            CHECK (ssh_port BETWEEN 1 AND 65535) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'server_status_metrics_check') THEN
        ALTER TABLE server_status ADD CONSTRAINT server_status_metrics_check CHECK (
            (uptime_seconds IS NULL OR uptime_seconds >= 0) AND
            (memory_used_pct IS NULL OR memory_used_pct BETWEEN 0 AND 100) AND
            (disk_root_used_pct IS NULL OR disk_root_used_pct BETWEEN 0 AND 100)
        ) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ip_allocations_kind_check') THEN
        ALTER TABLE ip_allocations ADD CONSTRAINT ip_allocations_kind_check
            CHECK (kind IN ('personal','server','vm','floating-ip','router-gw','dnat-vip')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ip_allocations_status_check') THEN
        ALTER TABLE ip_allocations ADD CONSTRAINT ip_allocations_status_check
            CHECK (status IN ('active','broken','reserved')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'openstack_memberships_confidence_check') THEN
        ALTER TABLE openstack_memberships ADD CONSTRAINT openstack_memberships_confidence_check
            CHECK (confidence IN ('declared','confirmed','local-only','control-only','conflict')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'openstack_instance_addresses_type_check') THEN
        ALTER TABLE openstack_instance_addresses ADD CONSTRAINT openstack_instance_addresses_type_check
            CHECK (address_type IN ('','fixed','floating')) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'openstack_instance_addresses_version_check') THEN
        ALTER TABLE openstack_instance_addresses ADD CONSTRAINT openstack_instance_addresses_version_check
            CHECK (ip_version IN (4,6)) NOT VALID;
    END IF;
END $$;

-- Inventory-owned observations should not outlive their inventory host. NOT
-- VALID keeps any existing orphan visible for cleanup while preventing new ones.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'server_status_server_fk') THEN
        ALTER TABLE server_status ADD CONSTRAINT server_status_server_fk
            FOREIGN KEY (hostname) REFERENCES servers(hostname)
            ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'server_capabilities_server_fk') THEN
        ALTER TABLE server_capabilities ADD CONSTRAINT server_capabilities_server_fk
            FOREIGN KEY (hostname) REFERENCES servers(hostname)
            ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'openstack_memberships_server_fk') THEN
        ALTER TABLE openstack_memberships ADD CONSTRAINT openstack_memberships_server_fk
            FOREIGN KEY (hostname) REFERENCES servers(hostname)
            ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'wg_interfaces_server_fk') THEN
        ALTER TABLE wg_interfaces ADD CONSTRAINT wg_interfaces_server_fk
            FOREIGN KEY (host) REFERENCES servers(hostname)
            ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'wg_peers_interface_fk') THEN
        ALTER TABLE wg_peers ADD CONSTRAINT wg_peers_interface_fk
            FOREIGN KEY (host, iface) REFERENCES wg_interfaces(host, iface)
            ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'wg_peer_status_peer_fk') THEN
        ALTER TABLE wg_peer_status ADD CONSTRAINT wg_peer_status_peer_fk
            FOREIGN KEY (host, iface, peer_pubkey) REFERENCES wg_peers(host, iface,peer_pubkey)
            ON UPDATE CASCADE ON DELETE CASCADE NOT VALID;
    END IF;
END $$;
