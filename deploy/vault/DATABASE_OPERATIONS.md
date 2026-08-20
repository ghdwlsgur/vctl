# Database operations

Application migrations own tables, columns, and constraints. Operations that
must observe production size or cannot run in a transaction stay here instead
of being hidden in application startup.

## Apply online indexes

Migration `022_dba_hardening.sql` protects new writes with `NOT VALID`
constraints but deliberately creates no indexes. Apply the matching indexes in
autocommit mode after migration 022 is present:

```bash
cd deploy/vault
PG_ADMIN_PASS=<root-pw> ./postgres-online-indexes.sh
```

The script uses `CREATE INDEX CONCURRENTLY IF NOT EXISTS`, so normal writes keep
running and an interrupted execution can be resumed. Monitor
`pg_stat_progress_create_index`; if PostgreSQL leaves an invalid index after a
failed build, drop that one concurrently and rerun the script.

After cleaning any legacy violations, validate the constraints individually in
a maintenance change. Check first:

```sql
SELECT conname, conrelid::regclass
FROM pg_constraint
WHERE conname LIKE '%_fk' OR conname LIKE '%_check'
ORDER BY conrelid::regclass::text, conname;
```

Then run `ALTER TABLE ... VALIDATE CONSTRAINT ...` one table at a time. Do not
put validation into application startup: its duration depends on production
row count.

## OpenStack missing-instance retention

`openstack_instances.missing_since` is an incident record, so vctl does not
guess a deletion period. The online index `idx_openstack_instances_missing`
makes a bounded archive job possible. Until the SRE team sets a retention
policy, alert on both rows and bytes:

```sql
SELECT count(*) AS missing_rows,
       min(missing_since) AS oldest,
       pg_total_relation_size('openstack_instances') +
       pg_total_relation_size('openstack_instance_addresses') AS retained_relations_bytes
FROM openstack_instances
WHERE missing_since IS NOT NULL;
```

Choose the archive/delete horizon from the incident-retention requirement, not
from current disk pressure. A future job should delete by indexed
`missing_since` in bounded batches, like audit pruning.

## `kernel_event` partition conversion

Do not convert the live heap in an application migration. The safe change is a
separate DBA project:

1. Create a new RANGE-partitioned table by `ts` with daily partitions and the
   required `(session_id, ts)` lookup index.
2. Dual-write or install a short-lived replication trigger.
3. Backfill one time window at a time and compare per-day counts and sampled
   session timelines.
4. Pause ingestion briefly, copy the tail, swap names, then verify grants,
   sequences, FK behavior, and `vctl session`.
5. Keep the old heap read-only through the rollback window.
6. Enforce retention by dropping whole expired partitions.

The cutover needs measured WAL, lock, and disk headroom. Do not start it unless
the old and new tables plus indexes fit simultaneously.

## Retention release ordering

`deploy/audit/prune-cronjob.yaml` references the release containing the hidden
`vctl prune` command. Publish that image to the trusted registry before applying
the manifest; otherwise Kubernetes correctly reports `ImagePullBackOff` rather
than silently running the obsolete pruner.
