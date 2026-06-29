-- Multi-homed hosts: a server can answer on several addresses (e.g. a primary
-- NIC plus floating VIPs). Track the extra addresses so `vctl ssh --server <ip>`
-- resolves any of them and `vctl list` shows them.
--   servers.extra_ips        operator-curated (vctl sync / dbedit) — survives sync.
--   server_status.observed_ips  node-agent auto-collected from the host's NICs.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS extra_ips INET[] NOT NULL DEFAULT '{}';
ALTER TABLE server_status ADD COLUMN IF NOT EXISTS observed_ips INET[] NOT NULL DEFAULT '{}';
