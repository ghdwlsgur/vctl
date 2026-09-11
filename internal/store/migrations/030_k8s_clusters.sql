-- Kubernetes clusters vctl can hand out access to.
--
-- A kubeconfig mixes two kinds of fact: where a cluster is (API server, CA,
-- how to reach it) and who you are to it (a certificate or a token). Only the
-- first kind lives here. The second is never stored — `vctl k8s token` mints
-- it per use from Vault's Kubernetes secrets engine, or reads a stand-in from
-- a KV path while a cluster is not yet wired to the engine. Postgres is read
-- by every authenticated vctl user through vctl-ro, so anything in this table
-- is visible to all of them; that is fine for an address and a CA and would
-- be a disaster for a credential.
--
-- reach says how a workstation gets there: 'tunnel' (through `vctl wg connect`,
-- so `vctl k8s use` writes a proxy-url) or 'direct'. token_source says where a
-- token comes from: 'vault:<mount>' for the secrets engine (roles viewer /
-- editor / admin under <mount>/creds/) or 'kv:<path>' for a stand-in secret
-- whose `token` field is used as is.
CREATE TABLE IF NOT EXISTS k8s_clusters (
    name             TEXT PRIMARY KEY,
    site             TEXT NOT NULL DEFAULT '',
    api_server       TEXT NOT NULL,                 -- https://host:port as a client dials it
    tls_server_name  TEXT NOT NULL DEFAULT '',      -- when api_server is a LB address the cert does not name
    ca_pem           TEXT NOT NULL DEFAULT '',      -- the cluster CA; empty = the client's trust store
    reach            TEXT NOT NULL DEFAULT 'tunnel'
                     CHECK (reach IN ('tunnel', 'direct')),
    token_source     TEXT NOT NULL
                     CHECK (token_source ~ '^(vault|kv):.+'),
    note             TEXT NOT NULL DEFAULT '',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by       TEXT NOT NULL DEFAULT ''
);

-- Production migration runs after group-role bootstrap, but local/test
-- databases may not have those roles.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_ro') THEN
        GRANT SELECT ON k8s_clusters TO vctl_ro;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vctl_rw') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON k8s_clusters TO vctl_rw;
    END IF;
END $$;
