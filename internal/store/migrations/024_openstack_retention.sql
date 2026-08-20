-- Dedicated least-privilege role for bounded deleted-VM history retention.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_openstack_pruner') THEN
        GRANT SELECT, DELETE ON openstack_instances TO vctl_openstack_pruner;
    END IF;
END $$;
