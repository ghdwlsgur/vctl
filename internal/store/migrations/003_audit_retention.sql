-- Retention support for kernel audit.
--
-- Raw kernel_event rows are high-volume and pruned on a short horizon; sessions
-- are small metadata kept far longer as the dataset index. Pruning is driven by
-- `vctl prune` (run by a CronJob) rather than in-DB jobs, mirroring Teleport's
-- storage-lifecycle model (structured rows in the DB, lifecycle elsewhere).
--
-- A plain ts index makes time-bounded DELETEs cheap (the existing
-- (hostname, ts) index is not selective for a global ts range scan).

CREATE INDEX IF NOT EXISTS idx_kernel_event_ts_prune ON kernel_event (ts);
