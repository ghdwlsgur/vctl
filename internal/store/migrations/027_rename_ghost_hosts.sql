-- openstack_control_hosts → openstack_ghost_hosts.
--
-- The old name said "control hosts" and the rows are the opposite: names the
-- control plane reports that matched NO inventory host — the ControlOnly
-- outcome of membership.Decide, which the listing already calls "ghosts". The
-- one thing the old name reliably produced was misreadings. It got one all the
-- way to production: the MOTD renderer took the table for a controller list
-- and printed "Controller : ?" on a farm whose actual controller was sitting
-- in server_capabilities the whole time.
--
-- Rename only — grants, data, and the (deployment_id, nova_hostname) key all
-- carry over. Constraint and index names are renamed too, so error messages
-- and \d output stop speaking the old vocabulary.
--
-- Coordination: binaries before this migration's release still query the old
-- name. Between applying this and upgrading the fleet, a reconcile tick fails
-- its ghost-row write (the run retries next tick) and a MOTD pass logs a read
-- warning (the banner file is left as-is). Both self-heal on upgrade; apply
-- the migration and roll the fleet in the same maintenance window.

ALTER TABLE openstack_control_hosts RENAME TO openstack_ghost_hosts;
ALTER INDEX idx_openstack_control_hosts_seen RENAME TO idx_openstack_ghost_hosts_seen;
ALTER TABLE openstack_ghost_hosts RENAME CONSTRAINT openstack_control_hosts_pkey TO openstack_ghost_hosts_pkey;
ALTER TABLE openstack_ghost_hosts RENAME CONSTRAINT openstack_control_hosts_deployment_id_fkey TO openstack_ghost_hosts_deployment_id_fkey;
