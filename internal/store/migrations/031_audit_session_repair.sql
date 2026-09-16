-- Repair audit_session rows written before the two host-side fixes landed.
--
-- Both causes are already fixed on the write path; this migration only cleans
-- up what the old binaries stored. Nothing here changes a schema.
--
-- 1. Negative durations. started_at comes from the login marker and is on the
--    *host's* clock (it has to be — it is part of the conflict key), while the
--    old EndSession stamped ended_at with the database clock. Any host running
--    ahead of Postgres produced a session that ended before it began: -3m15s,
--    -48s, -46s and friends, observed 2026-07-21 and still on display in
--    `vctl session --list`. store.EndSession now floors the write with
--    GREATEST(ended_at, started_at); the rows below predate that.
--
-- 2. Short OS hostnames. The login stamper writes $(hostname), so a farm host
--    whose OS name is 'aio01' recorded its sessions under 'aio01' while the
--    rest of the inventory — access_log included — calls it 'incheon-aio01'.
--    watch-sessions now takes --hostname and the Ansible role pins it to the
--    inventory name, but the old rows still carry the short one and no
--    --host filter finds them.
--
-- The hostname remap is deliberately conservative: it fires only when exactly
-- one inventory host can own the short name. 'gpu01' matches both
-- 'coex-rnd-gpu01' and 'incheon-gpu01', so it is left alone — a wrong
-- attribution is worse than a short name, and this is audit data.

-- 1. Floor the interval. GREATEST, not NULL: the session did end, and we know
--    when to within the clock skew. A zero-length session reads as "ended, and
--    the clocks disagreed"; a negative one reads as nonsense.
UPDATE audit_session
   SET ended_at = started_at
 WHERE ended_at IS NOT NULL
   AND ended_at < started_at;

-- 2. Remap unambiguous short hostnames onto their inventory names.
--    right(...) rather than LIKE: a hostname is user data and '_' is a LIKE
--    wildcard, so a pattern match here would be both wrong and silent.
UPDATE audit_session s
   SET hostname = m.inventory_name
  FROM (
        SELECT a.id, min(sv.hostname) AS inventory_name
          FROM audit_session a
          JOIN servers sv
            ON right(sv.hostname, length(a.hostname) + 1) = '-' || a.hostname
         WHERE a.hostname <> ''
           AND NOT EXISTS (SELECT 1 FROM servers e WHERE e.hostname = a.hostname)
         GROUP BY a.id
        HAVING count(*) = 1
       ) m
 WHERE s.id = m.id
   -- (hostname, session_leader_pid, started_at) is unique; never rename a row
   -- onto one that already exists under the inventory name.
   AND NOT EXISTS (
        SELECT 1 FROM audit_session c
         WHERE c.hostname = m.inventory_name
           AND c.session_leader_pid IS NOT DISTINCT FROM s.session_leader_pid
           AND c.started_at = s.started_at
           AND c.id <> s.id
       );
