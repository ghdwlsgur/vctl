-- The name people call a project by, next to the id nova reports.
--
-- Nova reports a VM's owner as a bare uuid. That is the right thing to key on —
-- it is the identifier and it does not change — but a listing of uuids does not
-- answer "whose VM is this", which is most of why anyone looks a VM up.
--
-- Kept alongside the id rather than replacing it, and refreshed on every
-- collection, because a project can be renamed. The id stays authoritative; this
-- column is what the last collection saw it called.
--
-- Empty when the collector could not reach Keystone or lacked the scope to list
-- projects. That reads as "not known", which is honest — the alternative is a
-- listing that loses VMs because their names could not be resolved.
ALTER TABLE openstack_instances
    ADD COLUMN IF NOT EXISTS project_name TEXT NOT NULL DEFAULT '';
