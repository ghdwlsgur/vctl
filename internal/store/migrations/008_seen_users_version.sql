-- Track which vctl version each person last logged in with, so an admin can see
-- who is behind. Recorded on `vctl login` (version at last login).

ALTER TABLE seen_users ADD COLUMN IF NOT EXISTS vctl_version TEXT;
