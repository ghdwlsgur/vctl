-- What an operator has declared about a deployment.
--
-- The same four words hosts use, for the same reason: observation cannot tell a
-- farm that is broken from one that is being rebuilt, and only a person knows
-- which. A reconcile failing every six hours against a farm somebody is
-- mid-upgrade on is expected; the same failure against a farm nobody touched is
-- news, and nothing in the collected data separates them.
--
-- Defaults to active so every existing deployment keeps reading as it did.
ALTER TABLE openstack_deployments
    ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'active';

-- Same vocabulary as servers.state, enforced the same way. A typo that reaches
-- this column would make a farm's declared state unreadable by anything that
-- switches on it.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'openstack_deployments_state_check'
    ) THEN
        ALTER TABLE openstack_deployments
            ADD CONSTRAINT openstack_deployments_state_check
            CHECK (state IN ('active','maintenance','broken','retired'));
    END IF;
END $$;

-- Set when the state was last changed, so "declared broken" can be read with
-- its age. A farm broken for an hour and one broken for a month are different
-- situations and the word alone does not say which.
ALTER TABLE openstack_deployments
    ADD COLUMN IF NOT EXISTS state_changed_at TIMESTAMPTZ;

-- Free text for why. The state says what to expect; this says what happened,
-- and an operator reading it a week later is usually asking the second.
ALTER TABLE openstack_deployments
    ADD COLUMN IF NOT EXISTS state_note TEXT NOT NULL DEFAULT '';
