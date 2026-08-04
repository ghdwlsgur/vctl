-- Whether a role is actually running, as opposed to deployed.
--
-- Roles used to require a running service, which made a farm's topology shrink
-- during an outage: a compute node whose nova-compute is down dropped out of
-- the compute count at exactly the moment somebody was looking because
-- something broke.
--
-- The role now records what the host is built to do, and this column records
-- whether it is doing it. The difference between the two is the outage.
--
-- Defaults true so existing rows keep reading as they did. They were written
-- under the old rule, where a row existing at all meant the service was up.
ALTER TABLE server_capabilities
    ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;

-- The common question is "which compute nodes are down", so role+active leads.
CREATE INDEX IF NOT EXISTS idx_server_capabilities_role_active
    ON server_capabilities (kind, role, active);
