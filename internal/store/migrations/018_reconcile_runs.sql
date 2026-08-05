-- What the reconciler did, and what the control plane said that nothing else
-- kept.
--
-- Both of these were printed and thrown away. The listing could say a host is
-- local-only but not whether that was decided an hour ago or three weeks ago,
-- and a nova record for a machine no inventory has was named on stdout and then
-- gone — which is exactly the row somebody wants when a host is missing.

-- One row per deployment: the state of its last reconcile.
--
-- Not an append-only log. The question this answers is "is this farm's
-- membership current, and if not why" — a question about now, asked while
-- looking at a listing. History of every six-hourly run would be a large table
-- to answer it from, and openstack_control_hosts below already keeps the part
-- that has to persist between runs.
CREATE TABLE IF NOT EXISTS openstack_reconcile_runs (
    deployment_id TEXT PRIMARY KEY REFERENCES openstack_deployments(id) ON DELETE CASCADE,

    -- Last attempt, whatever came of it, and the last one that actually
    -- settled anything. Apart because the gap between them is the outage: a
    -- farm reconciling every six hours and failing every time looks healthy on
    -- either timestamp alone.
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    succeeded_at  TIMESTAMPTZ,

    -- Whether the control plane answered fully. A partial answer may confirm
    -- but may not demote, so a caller reading membership needs to know this
    -- was the shape of the evidence behind it.
    complete      BOOLEAN NOT NULL DEFAULT false,

    -- Empty when the last run worked. Kept rather than cleared on the next
    -- attempt so a farm that fails intermittently still says what it failed at.
    last_error    TEXT NOT NULL DEFAULT '',

    confirmed     INTEGER NOT NULL DEFAULT 0,
    local_only    INTEGER NOT NULL DEFAULT 0,
    control_only  INTEGER NOT NULL DEFAULT 0,
    held          INTEGER NOT NULL DEFAULT 0,
    ambiguous     INTEGER NOT NULL DEFAULT 0
);

-- Hosts the control plane knows and the inventory does not.
--
-- These were reported and dropped. They are the most interesting rows the
-- reconciler produces: a nova service on a machine nobody has in inventory is
-- either a host somebody forgot to register, a name that drifted, or something
-- running that should not be. All three are worth a second look, and none of
-- them survives being printed once.
--
-- No foreign key to servers, by definition — the whole point is that there is
-- no such host.
CREATE TABLE IF NOT EXISTS openstack_control_hosts (
    deployment_id TEXT NOT NULL REFERENCES openstack_deployments(id) ON DELETE CASCADE,
    -- The name as the control plane gave it. Unresolved on purpose: resolving
    -- is what already failed.
    nova_hostname TEXT NOT NULL,

    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (deployment_id, nova_hostname)
);

CREATE INDEX IF NOT EXISTS idx_openstack_control_hosts_seen
    ON openstack_control_hosts (last_seen_at);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_ro') THEN
        GRANT SELECT ON openstack_reconcile_runs, openstack_control_hosts TO vctl_ro;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            openstack_reconcile_runs, openstack_control_hosts TO vctl_rw;
    END IF;
END $$;
