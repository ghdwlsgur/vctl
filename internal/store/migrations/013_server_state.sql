-- Operator-declared state for a host, kept apart from observed liveness.
--
-- The liveness column in `vctl list` and the ssh picker is derived: a fresh
-- node-agent heartbeat reads "up", an old one "stale", a sync-time probe "up~",
-- and no signal at all "down". That is the whole vocabulary observation can
-- offer, and it cannot answer the question an operator actually has in front of
-- a red row — is this box broken, is it in a planned window, or has nobody
-- installed the agent on it yet. All three look identical from here.
--
-- Only a person knows a machine is broken. So this column carries what a person
-- declared, and the listing shows it *next to* the observed value rather than
-- instead of it. Both facts stay on screen, and their disagreement is the
-- interesting signal: state=active with liveness=down is the row worth paging
-- about, state=broken with liveness=down is the row that is behaving as filed.
--
-- The vocabulary follows ip_allocations.status, which already spells the same
-- idea as active | broken | reserved for addresses. Reusing those words means an
-- operator does not learn two dialects for one concept.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'active';

-- The set is small and deliberate, so the database enforces it. Adding a state
-- later is a migration, which is the right amount of friction: every renderer
-- and every alert rule that switches on this column has to be taught the new
-- word, and a value that arrives without that is a row nothing knows how to draw.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'servers_state_check'
    ) THEN
        ALTER TABLE servers ADD CONSTRAINT servers_state_check
            CHECK (state IN ('active', 'maintenance', 'broken', 'retired'));
    END IF;
END $$;

-- Alerting and the listing both filter on "not active", which is the small
-- minority of rows.
CREATE INDEX IF NOT EXISTS idx_servers_state ON servers (state) WHERE state <> 'active';
