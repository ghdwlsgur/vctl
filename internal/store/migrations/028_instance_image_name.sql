-- The name of the image a VM was built from, next to the id nova reports.
--
-- Nova reports a VM's image as a bare uuid. That is the right thing to key on,
-- but the uuid answers none of the questions the image is looked up for — and
-- one of those questions is now operational: the login user a connection
-- should fall back to when root is refused is implied by the image ("what OS
-- is this"), and Glance is the only place its name exists.
--
-- Kept alongside the id rather than replacing it, and refreshed on every
-- collection, because an image can be renamed. Empty when the collector could
-- not reach Glance, which reads as "not known" — a connection then simply has
-- no image-derived candidate.
ALTER TABLE openstack_instances
    ADD COLUMN IF NOT EXISTS image_name TEXT NOT NULL DEFAULT '';
