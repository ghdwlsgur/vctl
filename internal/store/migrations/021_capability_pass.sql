-- Which probe pass a capability row belongs to, as a number instead of a time.
--
-- The reader has always needed two different facts out of one column. "Is this
-- still current" is a question about age, and "which rows are the latest pass"
-- is a question about identity — foldCapabilityRows reads every row older than
-- the newest as a role the host has stopped holding, so the second question has
-- to have an exact answer or a host silently loses roles.
--
-- observed_at answered both, and could only stay exact by being forced upward:
-- each pass wrote greatest(now(), max(observed_at) + 1 microsecond). That keeps
-- identity correct under any clock, and it makes age inherit. One row stamped
-- from a host running a day fast is never beaten by now() again, so every later
-- pass adds a microsecond to a timestamp that stays a day ahead — and the
-- listing reports data collected an hour ago as collected in the future,
-- permanently, with nothing on screen to say why.
--
-- pass_id carries the identity. It is a counter, so no clock anywhere can move
-- it, and observed_at is free to be what it says it is: when this was recorded.
-- Zero is the default because zero is what an agent that has not been upgraded
-- yet writes, and that agent's pass is genuinely newer than everything already
-- in the table. Schema goes first — the new writer needs this column and the
-- sequence to exist — so for as long as the rollout takes, every host is still
-- filing passes through the old statement, which names no pass_id at all.
ALTER TABLE server_capabilities
    ADD COLUMN IF NOT EXISTS pass_id BIGINT NOT NULL DEFAULT 0;

-- Which is why the history is numbered downward from zero rather than upward
-- from one. Numbering it 1..N would have put every existing row above the
-- writes arriving during the rollout, and the fold would have read each of
-- those hosts as having just dropped every role it holds and picked up the ones
-- it dropped last month — the exact failure the fold exists to prevent, on the
-- whole fleet, for as long as the upgrade took.
--
-- Descending rank per host and kind: the newest pass becomes -1, the one before
-- it -2. Rows sharing an observed_at were written by one pass, which is what the
-- old writer guaranteed and what the fold already assumed, so the set it reads
-- as current does not change at the moment this runs.
WITH ranked AS (
    SELECT hostname, kind, observed_at,
           -dense_rank() OVER (PARTITION BY hostname, kind ORDER BY observed_at DESC) AS pass
    FROM server_capabilities
)
UPDATE server_capabilities c
SET pass_id = ranked.pass
FROM ranked
WHERE c.hostname = ranked.hostname
  AND c.kind = ranked.kind
  AND c.observed_at = ranked.observed_at;

-- A sequence rather than max(pass_id) + 1 read inside the transaction. nextval
-- never hands the same value to two callers, so two agents writing for one
-- hostname at once — which happens when one is restarting and its replacement
-- has already started — get separate passes instead of merging into one.
--
-- It starts at 1, above both the backfilled history and the unnumbered writes
-- of the rollout window, so an upgraded agent's first pass wins against
-- everything either of them left.
CREATE SEQUENCE IF NOT EXISTS server_capability_pass_seq AS BIGINT START 1;

-- The fold asks for one host's newest pass, which is this index.
CREATE INDEX IF NOT EXISTS idx_server_capabilities_pass
    ON server_capabilities (hostname, kind, pass_id);

-- Rows already stamped ahead are brought back to when the database wrote them.
--
-- updated_at is the DB's own now() at write time, so it is the receipt time for
-- every row here — the same thing observed_at is supposed to mean now that it no
-- longer has to double as a sequence number. Only rows a skewed clock or the
-- inheritance above pushed ahead are touched; for every other row the two are
-- microseconds apart in the same transaction.
UPDATE server_capabilities
SET observed_at = updated_at
WHERE observed_at > updated_at;
