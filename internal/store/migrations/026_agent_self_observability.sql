-- What the agent can say about itself.
--
-- The heartbeat says the host is alive. It said nothing about whether the agent
-- was working, and that gap cost 57 days: one host's container runtime leaked
-- 16,383 mounts, /proc/self/mountinfo reached 2.8MB, something in the process
-- re-read it forever, and the unit sat at `active (running)` reporting nothing.
-- The row simply stopped being updated, which is what a powered-off host looks
-- like too.
--
-- Two columns, both about the agent rather than the host it runs on.
--
--   mount_count  how large the host's mount table is. The input that made the
--                agent expensive, and worth watching before it does — a mount
--                leak degrades everything that reads mountinfo, not just this.
--   collect_ms   how long gathering the status took. Collection is the half
--                that reads /proc, and reading /proc is what got expensive; a
--                collection that grows is the early half of the same failure.
--
-- collect_ms is the collection, not the whole cycle. The cycle includes the
-- write that carries this value, so a total would have to describe itself —
-- the row would always say zero, or say what the previous cycle cost, and both
-- are worse than measuring the half that actually moves.
--
-- Nullable rather than NOT NULL DEFAULT 0. Zero is a real measurement here — a
-- host with no /proc/self/mountinfo would report 0 mounts — and an agent that
-- predates these columns has not measured anything at all. Conflating "not
-- measured" with "measured zero" is what makes a dashboard quietly wrong.
ALTER TABLE server_status ADD COLUMN IF NOT EXISTS mount_count INTEGER;
ALTER TABLE server_status ADD COLUMN IF NOT EXISTS collect_ms  INTEGER;

-- Bounds, in the same spirit as 022's metrics check: a negative count or
-- duration is a bug in the writer, not a fact about a host.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'server_status_agent_metrics_check'
    ) THEN
        ALTER TABLE server_status ADD CONSTRAINT server_status_agent_metrics_check CHECK (
            (mount_count IS NULL OR mount_count >= 0) AND
            (collect_ms  IS NULL OR collect_ms  >= 0)
        );
    END IF;
END $$;

-- "which hosts have a mount table that is getting away from them", asked by the
-- daily digest. Partial: the rows worth looking at are the large ones, and on
-- this fleet that is a handful out of fifty.
CREATE INDEX IF NOT EXISTS idx_server_status_mount_count
    ON server_status (mount_count DESC) WHERE mount_count IS NOT NULL;
