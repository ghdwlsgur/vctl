-- What platforms a host is part of, and in what role.
--
-- Not columns on servers. The alternative was a nullable column per fact —
-- openstack_version, openstack_role, k8s_version — which is why that table
-- already carries ca_key_version and ca_applied_at that almost nothing reads.
-- A host can hold several roles in one platform (controller and network on a
-- small deployment) and be part of several platforms at once, and neither fits
-- in a column.
CREATE TABLE IF NOT EXISTS server_capabilities (
    hostname    TEXT NOT NULL,
    kind        TEXT NOT NULL,   -- openstack | kubernetes | ceph
    role        TEXT NOT NULL,   -- compute | controller | network | ...

    -- detected=false records a probe that ran and found nothing. Absence of a
    -- row is different: nothing has looked. Both are real answers and the
    -- listing has to tell them apart.
    detected    BOOLEAN NOT NULL,

    -- Per component, because a rolling upgrade leaves nova-compute, libvirt and
    -- qemu at different versions for weeks. One "release" string here would be
    -- wrong for at least one of them and unable to say which.
    components  JSONB NOT NULL DEFAULT '{}',
    details     JSONB NOT NULL DEFAULT '{}',

    -- last_error is kept alongside the last good answer rather than replacing
    -- it. A probe that fails today does not mean the host stopped being a
    -- compute node, and deleting the fact would make an outage look like a
    -- decommission.
    last_error  TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (hostname, kind, role)
);

-- The common query is "show me every compute node", so kind+role leads.
CREATE INDEX IF NOT EXISTS idx_server_capabilities_kind_role
    ON server_capabilities (kind, role);

-- Deployment membership, kept apart from the capability itself.
--
-- "This host runs nova-compute" and "this host belongs to the incheon farm" are
-- different claims with different evidence. The first is local and certain; the
-- second needs the control plane to confirm, and a host can be moving between
-- deployments or be managed by two. Many-to-many, so that is expressible.
CREATE TABLE IF NOT EXISTS openstack_deployments (
    id           TEXT PRIMARY KEY,   -- declared deployment id, or a synthesised one
    display_name TEXT NOT NULL DEFAULT '',
    region       TEXT NOT NULL DEFAULT '',
    keystone_url TEXT NOT NULL DEFAULT '',
    metadata     JSONB NOT NULL DEFAULT '{}',
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS openstack_memberships (
    hostname      TEXT NOT NULL,
    deployment_id TEXT NOT NULL REFERENCES openstack_deployments(id) ON DELETE CASCADE,

    -- How the membership was established, and how much it can be trusted:
    --   declared      an identifier placed on the host on purpose
    --   confirmed     local evidence and the control plane agree
    --   local-only    the host runs the services; the control plane has not confirmed
    --   control-only  registered centrally, but nothing was found on the host
    --   conflict      the evidence disagrees
    -- Automation should act on declared and confirmed only. The rest are
    -- observations, and treating an inference as a fact is the failure this
    -- column exists to prevent.
    confidence    TEXT NOT NULL DEFAULT 'local-only',
    evidence      JSONB NOT NULL DEFAULT '{}',
    observed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (hostname, deployment_id)
);

CREATE INDEX IF NOT EXISTS idx_openstack_memberships_deployment
    ON openstack_memberships (deployment_id);

-- Production runs this after the group-role bootstrap; local and test databases
-- have no group roles, so the grants are guarded the way the other migrations
-- guard theirs.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_ro') THEN
        GRANT SELECT ON server_capabilities, openstack_deployments, openstack_memberships TO vctl_ro;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_status') THEN
        -- The node agent writes its own capability rows through the same role it
        -- already uses for the heartbeat. No DELETE: a probe must not be able to
        -- remove a fact, only to record a newer one or an error beside it.
        GRANT SELECT, INSERT, UPDATE ON server_capabilities TO vctl_status;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            server_capabilities, openstack_deployments, openstack_memberships TO vctl_rw;
    END IF;
END $$;
