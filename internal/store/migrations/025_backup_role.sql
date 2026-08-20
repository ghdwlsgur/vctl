-- Keep the existing read-only backup group current when migrations add tables.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_backup') THEN
        GRANT SELECT ON ALL TABLES IN SCHEMA public TO vctl_backup;
        GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO vctl_backup;
        ALTER DEFAULT PRIVILEGES FOR ROLE vctl_owner IN SCHEMA public
            GRANT SELECT ON TABLES TO vctl_backup;
        ALTER DEFAULT PRIVILEGES FOR ROLE vctl_owner IN SCHEMA public
            GRANT SELECT ON SEQUENCES TO vctl_backup;
    END IF;
END $$;
