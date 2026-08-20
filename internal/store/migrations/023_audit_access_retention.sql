-- Complete the least-privilege retention contract. access_log must outlive
-- audit_session for attribution, but it must not grow forever. The dedicated
-- pruner can now remove it after the longer configured horizon.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_pruner') THEN
        GRANT SELECT, DELETE ON access_log TO vctl_pruner;
    END IF;
END $$;
