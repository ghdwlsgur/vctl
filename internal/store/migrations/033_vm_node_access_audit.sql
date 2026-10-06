-- Agent identities cover both physical hosts and OpenStack guests. Keep the
-- operator-controlled inventory authorization in the gateway; this audit
-- table records the target identity even when it is a Nova UUID.
ALTER TABLE node_access_audit
    DROP CONSTRAINT IF EXISTS node_access_audit_hostname_fkey;

ALTER TABLE node_access_audit
    ADD COLUMN IF NOT EXISTS target_kind TEXT NOT NULL DEFAULT 'host'
        CHECK (target_kind IN ('host', 'vm'));
