-- App-layer RBAC: command permissions assigned to groups, groups to users.
--
-- Vault does the coarse bootstrap (vctl-admin / vctl-user / vctl-ssh). This is
-- the fine-grained, CLI-managed layer (`vctl rbac ...`): which vctl commands a
-- non-admin may run, granted per group. Enforcement reads CommandsForUser;
-- admins (vctl-admin) bypass it. Read commands default-allow; mutate/connect
-- commands default-deny until a group grants them.

CREATE TABLE IF NOT EXISTS rbac_groups (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rbac_members (
    group_name TEXT NOT NULL REFERENCES rbac_groups (name) ON DELETE CASCADE,
    username   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_name, username)
);

CREATE INDEX IF NOT EXISTS idx_rbac_members_username ON rbac_members (username);

CREATE TABLE IF NOT EXISTS rbac_grants (
    group_name TEXT NOT NULL REFERENCES rbac_groups (name) ON DELETE CASCADE,
    command    TEXT NOT NULL, -- vctl command name (ssh, exec, sync, prune, ...) or '*'
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_name, command)
);
