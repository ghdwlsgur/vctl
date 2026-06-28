-- Known vctl users, recorded on `vctl login`, so the interactive RBAC assigner
-- (`vctl rbac assign`) can offer anyone who has authenticated, plus existing
-- members. Identity is the OIDC
-- preferred_username (the same value used for audit attribution).

CREATE TABLE IF NOT EXISTS seen_users (
    username   TEXT PRIMARY KEY,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now()
);
