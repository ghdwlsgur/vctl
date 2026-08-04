-- VMs, per deployment.
--
-- Deliberately not in servers. That table is the physical inventory — machines
-- somebody racked, with jump chains and SSH users and an agent on them. A VM is
-- a different kind of thing with a different lifecycle: it is created and
-- destroyed by an API, it has no place in a jump chain, and its name is not
-- unique across the fleet. Mixing them would make `vctl ssh` offer to connect
-- to rows that no host ever answers for.
--
-- The chain this completes:
--
--   OpenStack farm → physical compute host → VM → Kubernetes node → cluster
--
-- and the two joins that carry it are hypervisor_hostname (to the physical
-- host, through the same name matching the reconciler uses) and instance_id
-- (to a Kubernetes node's spec.providerID, openstack:///<uuid>).
CREATE TABLE IF NOT EXISTS openstack_instances (
    deployment_id TEXT NOT NULL REFERENCES openstack_deployments(id) ON DELETE CASCADE,
    -- Nova's UUID. Unique within a deployment, and the key Kubernetes uses to
    -- name the same machine in spec.providerID.
    instance_id   TEXT NOT NULL,

    project_id    TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',

    -- What nova says about it now. Three fields because they answer different
    -- questions: status is the API's view (ACTIVE/SHUTOFF/ERROR), power_state
    -- is the hypervisor's, and task_state is non-empty only mid-operation —
    -- a VM stuck in "migrating" for an hour is a fault that neither of the
    -- other two shows.
    status        TEXT NOT NULL DEFAULT '',
    power_state   TEXT NOT NULL DEFAULT '',
    task_state    TEXT NOT NULL DEFAULT '',

    availability_zone   TEXT NOT NULL DEFAULT '',
    -- nova's name for the host, not the inventory's. Kept as reported so the
    -- join can be re-derived when the naming rules change; resolving it here
    -- would bake today's matching into stored data.
    hypervisor_hostname TEXT NOT NULL DEFAULT '',

    flavor_id     TEXT NOT NULL DEFAULT '',
    image_id      TEXT NOT NULL DEFAULT '',

    -- nova's timestamps, kept apart from ours. created_at is when the VM was
    -- made; observed_at is when we last saw it. Conflating them would make a
    -- long-lived VM look freshly created after every collection.
    created_at    TIMESTAMPTZ,
    updated_at    TIMESTAMPTZ,
    observed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Set when a collection that reached the deployment did not list this VM,
    -- cleared when it comes back.
    --
    -- Rows are not deleted on absence. A VM missing from one listing may have
    -- been deleted, or the query may have been scoped wrong, or nova may have
    -- been mid-restart — and a row that vanishes takes with it the only record
    -- that the machine ever existed, which is exactly what somebody asks about
    -- after an incident. The age of this column is how a caller decides.
    missing_since TIMESTAMPTZ,

    PRIMARY KEY (deployment_id, instance_id)
);

-- "which VMs are on this host" is the question the physical-host join asks.
CREATE INDEX IF NOT EXISTS idx_openstack_instances_hypervisor
    ON openstack_instances (deployment_id, hypervisor_hostname);

-- The Kubernetes join arrives with a bare UUID and no deployment: a node's
-- providerID is openstack:///<uuid> and nothing else. This index is what lets
-- that be answered without scanning.
CREATE INDEX IF NOT EXISTS idx_openstack_instances_id
    ON openstack_instances (instance_id);

CREATE INDEX IF NOT EXISTS idx_openstack_instances_project
    ON openstack_instances (deployment_id, project_id);

-- Addresses, separately, because a VM has several.
--
-- One row per address rather than a JSON blob on the instance: the common query
-- is "which VM has this IP", asked while somebody is looking at a connection
-- log, and that is an index lookup here and a scan there.
CREATE TABLE IF NOT EXISTS openstack_instance_addresses (
    deployment_id TEXT NOT NULL,
    instance_id   TEXT NOT NULL,
    -- The neutron network the address came from, as nova groups them.
    network_name  TEXT NOT NULL DEFAULT '',
    address       TEXT NOT NULL,
    -- fixed | floating. A floating address is the one reachable from outside,
    -- and telling them apart is most of why anyone looks this up.
    address_type  TEXT NOT NULL DEFAULT '',
    ip_version    SMALLINT NOT NULL DEFAULT 4,

    PRIMARY KEY (deployment_id, instance_id, address),
    FOREIGN KEY (deployment_id, instance_id)
        REFERENCES openstack_instances (deployment_id, instance_id) ON DELETE CASCADE
);

-- "which VM has this IP" — the reason this table is not a JSON column.
CREATE INDEX IF NOT EXISTS idx_openstack_instance_addresses_address
    ON openstack_instance_addresses (address);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_ro') THEN
        GRANT SELECT ON openstack_instances, openstack_instance_addresses TO vctl_ro;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            openstack_instances, openstack_instance_addresses TO vctl_rw;
    END IF;
END $$;
